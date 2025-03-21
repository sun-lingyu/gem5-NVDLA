import sys
import shutil
import os
import argparse
import re
import errno
import matplotlib.pyplot as plt
import matplotlib.patches as patches

sys.path.append(os.path.dirname(__file__))
from parse_qemu_log import *


class BaseRemapper:
    def __init__(self, in_dir, model_name):
        """ paths """
        self.in_dir = in_dir    # expect in_dir to be VP out dir
        self.model_name = model_name

        """ workload-related info """
        self.out_dir = None
        self.sim_dir_host = None
        self.testcase_str = None

        """ mapping parameters """
        self.alignment = 0x1000

    def testcase_init(self, out_dir, sim_dir, testcase_str):
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.sim_dir_host = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../mnt" + sim_dir))
        self.testcase_str = testcase_str

    def aligned_ceil(self, addr):
        return ((addr - 0x1) // self.alignment + 1) * self.alignment

    """
    @output: if not None, it's the shell command to be executed to do some heavy math during remap decision.
    """
    def compute_remap_decision(self):
        pass

    # for more complex CVSRAM utilizing methods, heavy computation is needed. We need to let multiple testcases
    # do the computation in parallel and then collect the results one-by-one.
    def collect_remap_decision(self):
        pass

    def write_to_files(self):
        pass

    def copy_output_to_img(self):
        os.system("sudo mkdir -p " + self.sim_dir_host)
        files = os.listdir(self.out_dir)
        for file in files:
            if "rd_only_var_log" in file or ".bin" in file:
                os.system("sudo cp " + os.path.join(self.out_dir, file) + " " + self.sim_dir_host)

class IdentityRemapper(BaseRemapper):
    def __init__(self, in_dir, model_name):
        super(IdentityRemapper, self).__init__(in_dir, model_name)

        """ workload-related info """
        self.workload = Workload(in_dir)

    def testcase_init(self, out_dir, sim_dir, testcase_str=""):
        assert os.path.abspath(out_dir) == os.path.abspath(self.in_dir)
        BaseRemapper.testcase_init(self, out_dir, sim_dir, testcase_str)

    def compute_remap_decision(self, remap_input=[], remap_output=[]):
        pass

    def write_to_files(self):
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../input_txn_to_verilator.pl")
        os.system("perl " + script_path + " " + os.path.join(self.out_dir, "input.txn") + " " +
                  os.path.join(self.out_dir, "trace.bin"))
        rd_var_log_path = os.path.join(self.out_dir, "rd_only_var_log")
        """ generate rd_only_var_log """
        if not os.path.exists(rd_var_log_path):
            with open(rd_var_log_path, "wb") as fp:
                for rd_only_var in self.workload.rd_only_tbs:
                    tb = self.workload.tb[rd_only_var]
                    assert(tb.num_batch == 1)
                    fp.write(tb.addrs[0].to_bytes(4, byteorder="little", signed=False))
                    fp.write(tb.size.to_bytes(4, byteorder="little", signed=False))

class CVSRAMRemapper(BaseRemapper):
    def __init__(self, in_dir, model_name):
        super(CVSRAMRemapper, self).__init__(in_dir, model_name)

        """ mapping parameters """
        self.num_cvsram = 0
        self.cvsram_base_addrs = []
        self.cvsram_sizes = []
        self.assoc_reg_bits = {    # {reg: (associated_reg, bit)} -> &= ~(1<<bit); bit value: 0: CVSRAM, 1: DRAM
            0x4000: (0x4014, 0), 0x4004: (0x4014, 0),
            0x4008: (0x4014, 1), 0x400c: (0x4014, 1),
            0x5030: (0x502c, 0), 0x5034: (0x502c, 0),
            0x5038: (0x502c, 0), 0x503c: (0x502c, 0),
            0x5078: (0x5074, 0), 0x507c: (0x5074, 0),
            0xa018: (0xa074, 0), 0xa01c: (0xa074, 0),
            0xa02c: (0xa028, 5), 0xa030: (0xa028, 5),
            0xa044: (0xa040, 5), 0xa048: (0xa040, 5),
            0xa05c: (0xa058, 5), 0xa060: (0xa058, 5),
            0xb048: (0xb0b4, 0), 0xb04c: (0xb0b4, 0),
            0xc01c: (0xc02c, 0), 0xc020: (0xc02c, 0),
            # 0xd060: (), 0xd064: (),
            0xd070: (0xd080, 0), 0xd074: (0xd080, 0),
            0xe018: (0xe028, 0), 0xe01c: (0xe028, 0),
            0xf050: (0xf060, 0), 0xf054: (0xf060, 0),
            0x1001c: (0x10010, 0), 0x10020: (0x10010, 0),
            0x10038: (0x10030, 0), 0x1003c: (0x10030, 0)
        }   # these are from nvdla/hw/cmod/include/arnvdla.h

    def testcase_init(self, out_dir, sim_dir, testcase_str):
        BaseRemapper.testcase_init(self, out_dir, sim_dir, testcase_str)

    def set_cvsram_param(self, num_cvsram, cvsram_base_addrs, cvsram_sizes):
        self.num_cvsram = num_cvsram
        self.cvsram_base_addrs = cvsram_base_addrs
        self.cvsram_sizes = cvsram_sizes

    def change_ram_type_to_cvsram(self, raw_lines, modified_lines, line_id, modify_status):
        line = raw_lines[line_id]
        # use regex to get the register
        reg_match = re.search(r'#\s?(0x[0-9a-f]{1,2}0[0-9a-f]{2})', line)
        if reg_match is None:       # not register txns. May be {load|dump}_mem
            return
        reg = int(reg_match.group(1), 16)
        ram_type_reg, ram_type_bit = self.assoc_reg_bits[reg]

        explore_id = line_id - 1
        while explore_id >= 0:
            ram_reg_match = re.search(r'#\s?(0x[0-9a-f]{1,2}0[0-9a-f]{2})', raw_lines[explore_id])
            if ram_reg_match is None:
                break
            if ram_reg_match.group(0)[2] != reg_match.group(0)[2] or \
                    ram_reg_match.group(0)[3] != reg_match.group(0)[3]:
                # only explore registers in the same reg group and continuous lines
                break
            if int(ram_reg_match.group(1), 16) == ram_type_reg and not modify_status[explore_id]:
                reg_val_match = re.search(r'_reg\s0xffff[0-9a-f]{4}\s(0x[0-9a-f]{8})', raw_lines[explore_id])
                old_val_str = reg_val_match.group(1)
                new_val = int(old_val_str, 16) & ~(1 << ram_type_bit)   # change to CVSRAM
                new_val_str = f"{new_val:#0{10}x}"
                modified_lines[explore_id] = new_val_str.join(raw_lines[explore_id].rsplit(old_val_str, 1)) # reverse_replace
                modify_status[explore_id] = True
            explore_id -= 1

        explore_id = line_id + 1
        while explore_id < len(raw_lines):
            ram_reg_match = re.search(r'#\s?(0x[0-9a-f]{1,2}0[0-9a-f]{2})', raw_lines[explore_id])
            if ram_reg_match is None:
                break
            if ram_reg_match.group(0)[2] != reg_match.group(0)[2] or \
                    ram_reg_match.group(0)[3] != reg_match.group(0)[3]:
                # only explore registers in the same reg group and continuous lines
                break
            if int(ram_reg_match.group(1), 16) == ram_type_reg and not modify_status[explore_id]:
                reg_val_match = re.search(r'_reg\s0xffff[0-9a-f]{4}\s(0x[0-9a-f]{8})', raw_lines[explore_id])
                old_val_str = reg_val_match.group(1)
                new_val = int(old_val_str, 16) & ~(1 << ram_type_bit)   # change to CVSRAM
                new_val_str = f"{new_val:#0{10}x}"
                modified_lines[explore_id] = new_val_str.join(raw_lines[explore_id].rsplit(old_val_str, 1)) # reverse_replace
                modify_status[explore_id] = True
            explore_id += 1

class SingleAccelCVSRAMRemapper(CVSRAMRemapper):
    def __init__(self, in_dir, model_name):
        super(SingleAccelCVSRAMRemapper, self).__init__(in_dir, model_name)

        """ workload-related info """
        self.workload = Workload(in_dir)

        """ testcase-related decisions """
        self.mapping = {}   # {addr_in_dram: addr_in_cvsram}

    def testcase_init(self, out_dir, sim_dir, testcase_str):
        BaseRemapper.testcase_init(self, out_dir, sim_dir, testcase_str)
        self.mapping.clear()

        for root, dirs, files in os.walk(self.in_dir):
            if os.path.abspath(root) == os.path.abspath(self.in_dir):
                # create symbolic links of *.dat files under root in out_dir
                for file in files:
                    if file.endswith(".dat"):
                        src = os.path.abspath(os.path.join(root, file))
                        link = os.path.abspath(os.path.join(out_dir, file))
                        try:
                            os.symlink(src, link)
                        except OSError as e:
                            if e.errno == errno.EEXIST:
                                os.remove(link)
                                os.symlink(src, link)
                            else:
                                raise e

    def set_cvsram_param(self, num_cvsram, cvsram_base_addrs, cvsram_sizes):
        CVSRAMRemapper.set_cvsram_param(self, num_cvsram, cvsram_base_addrs, cvsram_sizes)
        assert num_cvsram == 1

    def write_to_files(self):
        """ modify input.txn """
        with open(os.path.join(self.in_dir, "input.txn")) as fp:
            raw_txn_lines = fp.readlines()
        new_lines = [str(line) for line in raw_txn_lines]
        modify_status = [False for _ in range(len(raw_txn_lines))]  # False means not modified by remapping yet

        for orig_addr, mapped_addr in self.mapping.items():
            for line_id, line in enumerate(raw_txn_lines):
                if hex(orig_addr) in line and not modify_status[line_id]:
                    new_lines[line_id] = line.replace(hex(orig_addr), hex(mapped_addr), 1)
                    # the parameter "1" is crucial since in {load|dump}_mem, files are named with addresses
                    # we want to keep the file name unchanged after remapping
                    modify_status[line_id] = True

                    self.change_ram_type_to_cvsram(raw_txn_lines, new_lines, line_id, modify_status)

        out_txn_path = os.path.join(self.out_dir, self.testcase_str + "_input.txn")
        rd_var_log_path = os.path.join(self.out_dir, self.testcase_str + "_rd_only_var_log")
        with open(out_txn_path, "w") as fp:
            fp.writelines(new_lines)
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../input_txn_to_verilator.pl")
        os.system("perl " + script_path + " " + out_txn_path + " " +
                  os.path.join(self.out_dir, self.testcase_str + "_trace.bin"))

        """ modify rd_only_var_log """
        with open(rd_var_log_path, "wb") as fp:
            for rd_only_var in self.workload.rd_only_tbs:
                tb = self.workload.tb[rd_only_var]
                assert tb.num_batch == 1
                if tb.addrs[0] not in self.mapping.keys():
                    fp.write(tb.addrs[0].to_bytes(4, byteorder="little", signed=False))
                    fp.write(tb.size.to_bytes(4, byteorder="little", signed=False))

class ActPinRemapper(SingleAccelCVSRAMRemapper):
    def __init__(self, in_dir, model_name):
        super(ActPinRemapper, self).__init__(in_dir, model_name)

        """ workload-related info """
        self.last_tick = len(self.workload.raw_addr_log) - 1

    def compute_remap_decision(self, remap_input=[], remap_output=[]):
        itm_acts_file = os.path.join(self.in_dir, "intermediate_acts")

        print("\nself.workload.in_tb: ")
        for tensor in self.workload.in_tb:
            buffer = self.workload.tb[tensor]
            print(tensor, " " + str(buffer.liveness) + " " + str(buffer.size) + " " + str(list(map(hex, buffer.addrs))) + " " + str(buffer.num_access) + " " + str(buffer.num_batch))

        print("\nself.workload.w_tb: ")
        for tensor in self.workload.w_tb:
            buffer = self.workload.tb[tensor]
            print(tensor, " " + str(buffer.liveness) + " " + str(buffer.size) + " " + str(list(map(hex, buffer.addrs))) + " " + str(buffer.num_access) + " " + str(buffer.num_batch))

        print("\nself.workload.itm_act_tb: ")
        for tensor in self.workload.itm_act_tb:
            buffer = self.workload.tb[tensor]
            print(tensor, " " + str(buffer.liveness) + " " + str(buffer.size) + " " + str(list(map(hex, buffer.addrs))) + " " + str(buffer.num_access) + " " + str(buffer.num_batch))
        
        print("\nself.workload.out_tb: ")
        for tensor in self.workload.out_tb:
            buffer = self.workload.tb[tensor]
            print(tensor, " " + str(buffer.liveness) + " " + str(buffer.size) + " " + str(list(map(hex, buffer.addrs))) + " " + str(buffer.num_access) + " " + str(buffer.num_batch))
        # exit()

        write_solver_input(itm_acts_file, self.workload, log_weights=False, remap_input=remap_input, remap_output=remap_output)

        # call the gurobi solver
        gurobi_out_path = os.path.join(self.out_dir, self.testcase_str + "_alloc_result")
        os.system("cd " + os.path.join(os.path.dirname(__file__), "CVSRAMAlloc") + " && make ActAlloc")
        return ["cd " + os.path.join(os.path.dirname(__file__), "CVSRAMAlloc") + " && ./ActAlloc " + itm_acts_file +
                " " + gurobi_out_path + " " + str(self.cvsram_sizes[0]) + " > " +
                os.path.join(self.out_dir, self.testcase_str + "_gurobi_stdout")]

    def collect_remap_decision(self):
        gurobi_in_path = os.path.join(self.in_dir, "intermediate_acts")
        gurobi_out_path = os.path.join(self.out_dir, self.testcase_str + "_alloc_result")
        relative_map = collect_gurobi_results(self.workload, self.cvsram_sizes[0], gurobi_out_path, gurobi_in_path)
        for tb_name, rel_addr in relative_map.items():
            buffer = self.workload.tb[tb_name]
            buffer_actual_size = buffer.size * buffer.num_batch if tb_name in self.workload.itm_act_tb else buffer.size # input and output are multi-batch NCHW buffers
            for ts_name in buffer.tsd_list:
                ts = self.workload.ts[ts_name]
                for batch_id in range(ts.num_batch):
                    assert(buffer_actual_size % buffer.num_batch == 0)
                    batch_offset = buffer_actual_size // buffer.num_batch * batch_id
                    to_map_addr = self.cvsram_base_addrs[0] + rel_addr + batch_offset + ts.addrs[batch_id] - buffer.addrs[batch_id]
                    if ts.addrs[batch_id] in self.mapping:
                        assert to_map_addr == self.mapping[ts.addrs[batch_id]]
                    else:
                        self.mapping[ts.addrs[batch_id]] = to_map_addr

def write_solver_input(file_path, workload, log_weights, remap_input=[], remap_output=[]):
    tensors_remapped = workload.itm_act_tb[:]
    for idx in remap_input:
        tensors_remapped.append(workload.in_tb[idx])
    for idx in remap_output:
        tensors_remapped.append(workload.out_tb[idx])
    print("tensors_remapped:", tensors_remapped)
    with open(file_path, "w") as fp:
        for tb_name in tensors_remapped:
            buffer = workload.tb[tb_name]
            buffer_actual_size = buffer.size * buffer.num_batch if tb_name in workload.itm_act_tb else buffer.size # input and output are multi-batch NCHW buffers
            fp.write(str(buffer.tb_name) + " " + str(buffer.liveness[0]) + " " + str(buffer.liveness[1]) + " " + str(buffer_actual_size) + " " + str(buffer.num_access) + " " + hex(buffer.addrs[0]) + " ")
            last_aligned_addr = last_aligned(buffer.addrs[0], buffer.size, workload.axi_width)
            for id_rw in workload.addr_log[last_aligned_addr]:
                fp.write(id_rw[1] + " ")
            fp.write("\n")

        if log_weights:
            last_tick = len(workload.raw_addr_log) - 1
            for w in workload.w_tb:
                weight_tb = workload.tb[w]
                assert len(weight_tb.tsd_list) == 1
                fp.write("0 " + str(last_tick) + " " + str(weight_tb.size) +
                         "1 " + hex(weight_tb.addrs[0]) + " r\n")

def collect_gurobi_results(workload, cvsram_size, gurobi_out_path, gurobi_in_path):
    # read results from the solver and draw the CVSRAM occupation figure
    occ_fig = plt.figure(figsize=(12.8, 9.6))
    ax1 = occ_fig.add_subplot(111)
    plt.xlim(xmin=0, xmax=len(workload.raw_addr_log))
    plt.ylim(ymin=0, ymax=cvsram_size)

    with open(gurobi_in_path) as fp:
        in_lines = fp.readlines()

    with open(gurobi_out_path) as fp:
        out_lines = fp.readlines()

    with open(gurobi_out_path+"_tmp", "wt") as fp:
        relative_mapping = {}   # {data_desc(inside a pipeline stage): mapping position in a CVSRAM}
        for line_id, line in enumerate(out_lines):
            words = line.split()
            attrs = in_lines[line_id].strip().split()
            is_input = (attrs[3] == "1") and (attrs[5] == "w")      # weights will only be used once
            if words[0] == '1':
                tb_name = attrs[0]
                buffer = workload.tb[tb_name]
                buffer_actual_size = buffer.size * buffer.num_batch if tb_name in workload.itm_act_tb else buffer.size
                relative_mapping[tb_name] = int(words[1])
                ax1.add_patch(patches.Rectangle((buffer.liveness[0], int(words[1])),
                                                buffer.liveness[1] - buffer.liveness[0], buffer_actual_size,
                                                linewidth=1, edgecolor='black'))
                fp.write(f"{tb_name} addr {int(words[1])}, size {buffer_actual_size}\n")
            else:
                assert(0) # TODO: handle allocation failure

    ylabels = map(lambda t: '0x%x' % int(t), ax1.get_yticks())
    ax1.set_yticklabels(ylabels)
    ax1.ticklabel_format(style='sci', scilimits=(-1, 2), axis='x')
    plt.title("Buffer Allocation Result on CVSRAM size = 0x%x Bytes" % cvsram_size)
    plt.xlabel("Logical Order")
    plt.ylabel("CVSRAM Address")
    plt.rcParams.update({'font.size': 22})
    plt.tight_layout()
    occ_fig.savefig(gurobi_out_path + "_vis.png", dpi=400)

    return relative_mapping
