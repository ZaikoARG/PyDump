# Copyright © 2022, ZaikoARG.
# All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# https://github.com/ZaikoARG | Discord: ZaikoARG#1187

import os
import sys
import argparse
import psutil
import platform
from termcolor import colored
from ctypes import *
from ctypes.wintypes import *


# Banner
banner = colored(r"""
    ____        ____                      
   / __ \__  __/ __ \__  ______ ___  ____ 
  / /_/ / / / / / / / / / / __ `__ \/ __ \
 / ____/ /_/ / /_/ / /_/ / / / / / / /_/ /
/_/    \__, /_____/\__,_/_/ /_/ /_/ .___/ 
      /____/                     /_/          
""", 'red', attrs=["bold"])


# Permissions for Process Handle
permissions = {
    "PROCESS_QUERY_INFORMATION":0x0400,
    "PROCESS_VM_OPERATION": 0x0008,
    "PROCESS_VM_READ": 0x0010,
    "PROCESS_VM_WRITE": 0x0020,
}


# Types of Region Memory
memory_types = {
    'IMAGE':0x1000000,
    'PRIVATE':0x20000,
    'MAPPED':0x40000,
}


# C Struct for GetSystemInfo Function
class SYSTEM_INFO(Structure):
    _fields_ = [
        ('wProcessorArchitecture', WORD),
        ('wReserved', WORD),
        ('dwPageSize', DWORD),
        ('lpMinimumApplicationAddress', c_void_p),
        ('lpMaximumApplicationAddress', c_void_p),
        ('dwActiveProcessorMask', c_void_p),
        ('dwNumberOfProcessors', DWORD),
        ('dwProcessorType', DWORD),
        ('dwAllocationGranularity', DWORD),
        ('wProcessorLevel', WORD),
        ('wProcessorRevision', WORD),
        ]


# C Struct of 32 Bits Memory Info
class MemoryInfoStruct32(Structure):
    _fields_ = [
        ('BaseAddress', DWORD),
        ('AllocationBase', DWORD),
        ('AllocationProtect', DWORD),
        ('RegionSize', DWORD),
        ('State', DWORD),
        ('Protect', DWORD),
        ('Type', DWORD),
        ]


# C Struct of 64 Bits Memory Info
class MemoryInfoStruct64(Structure):
        _fields_ = [
        ('BaseAddress', c_ulonglong),
        ('AllocationBase', c_ulonglong),
        ('AllocationProtect', DWORD),
        ('__alignment1', DWORD),
        ('RegionSize', c_ulonglong),
        ('State', DWORD),
        ('Protect', DWORD),
        ('Type', DWORD),
        ('__alignment2', DWORD),
        ]


# Windows Process Class
class WindowsProcess:
    def __init__(self, process_id: int):
        # Get Process handle with OpenProcess
        self.process_handle = windll.kernel32.OpenProcess(
            permissions["PROCESS_QUERY_INFORMATION"] |
            permissions["PROCESS_VM_OPERATION"] |
            permissions["PROCESS_VM_READ"],
            False,
            process_id)
    
    def get_region_info(self, address: int, memory_info: MemoryInfoStruct32 | MemoryInfoStruct64):
        """
        Get Memory Region Info

        Args:
            address (int): Memory Address
            memory_info (MemoryInfoStruct32 | MemoryInfoStruct64): A MemoryInfo C Struct to save the data.

        Returns:
            MemoryInfoStruct32 | MemoryInfoStruct64: The same MemoryInfo C Struct filled with the data.
        """
        memory_info_pointer = byref(memory_info) # Getting the pointer pointing towards MemoryInfoStruct
        
        memory_info_size = sizeof(memory_info) # Getting the size of MemoryInfoStruct
        
        # Using VirtualQueryEx to get the RegionInfo
        virtual_query_ex = windll.kernel32.VirtualQueryEx(
            self.process_handle,
            c_void_p(address),
            memory_info_pointer, # Here we use the pointer for the function to fill with data our MemoryInfoStruct.
            memory_info_size) # The size of the Structure so the Function know how much data fill.

        # If the sizes don't match we have a error.
        if virtual_query_ex != memory_info_size:
            print(colored("! Error getting VirtualMemoryEx at address: {}".format(address), "red"))
            sys.exit(1)
        
        return memory_info
            
    def get_memory_regions(self, image=False, mapped=False, private=False):
        """
        Map and Return all Memory Regions of a Process

        Returns:
            List: Containing tuples with (start_address, stop_address). 
        """
        if image and not mapped and not private:
            memory_type = memory_types['IMAGE']
        elif mapped and not image and not private:
            memory_type = memory_types['MAPPED']
        elif private and not image and not mapped:
            memory_type = memory_types['PRIVATE']
        elif not private and not image and not mapped:
            memory_type = None
        else:
            raise ArgumentError("Only can use one flag at time")
            
        # Checking if Python is 64 or 32 Bits
        if sizeof(c_void_p) == 8:
            memory_info = MemoryInfoStruct64() # Setting the MemoryInfoStruct for 64 bits
        else:
            memory_info = MemoryInfoStruct32() # Setting the MemoryInfoStruct for 32 bits
        
        sys_info = SYSTEM_INFO() # Setting the SystemInfo struct for the output of the GetSystemInfo Function
        sys_info_pointer = byref(sys_info) # Getting the pointer pointing towards MemoryInfoStruct
        windll.kernel32.GetSystemInfo(sys_info_pointer) # Getting the size of MemoryInfoStruct
        
        minAddress = sys_info.lpMinimumApplicationAddress # Getting the Minimum Application Address for our system.
        maxAddress = sys_info.lpMaximumApplicationAddress # Getting the Maximum Application Address for our system.
        
        regions = []
        
        address = minAddress
        
        while (address < maxAddress):
            region_info = self.get_region_info(address, memory_info) # Getting region info for this address.
            endAddress = address + region_info.RegionSize # Calculate End Address for this region.
            if ((region_info.Type == memory_type or memory_type is None) and region_info.State == 0x1000 
                and region_info.Protect & 0x20 | 0x40 | 0x04 != 0):
                
                regions.append((address, endAddress)) # Adding Address to List
            
            address += region_info.RegionSize # Continue to next Region
        
        return regions
        
    def read_memory(self, address: int, size: int):
        """
        Read Memory data on a given address.

        Arguments:
            address (int): Memory Address to read
            size (int): Size of the data to read.

        Returns:
            Array[c_char]: Readed Buffer
        """
        oBuffer = create_string_buffer(size) # Setting the Buffer
        
        windll.kernel32.ReadProcessMemory(
            self.process_handle,
            c_void_p(address),
            byref(oBuffer), # Pointer for the buffer
            sizeof(oBuffer), # Size of Buffer
            None)
        
        return oBuffer
    

# Linux Process Class
class LinuxProcess:
    def __init__(self, process_id: int):
        self.process_id = process_id
    
    def get_memory_regions(self, read_only=False):
        """
        Map and Return all Memory Regions of a Process

        Returns:
            List: Containing tuples with (start_address, stop_address). 
        """
        regions = []
        
        with open("/proc/{}/maps".format(self.process_id), "r") as proc_map:
            for line in proc_map.readlines():
                region, privileges = line.split()[0:2]
                
                if "r" not in privileges and read_only: # If page don't have read privileges, continue
                    continue
                
                region_start = int(region.split("-")[0], 16)
                region_end = int(region.split("-")[1], 16)
                regions.append((region_start, region_end))
                
        return regions

    def read_memory(self, address: int, size: int):
        """
        Read Memory data on a given address.

        Arguments:
            address (int): Memory Address to read
            size (int): Size of the data to read.

        Returns:
            Array[c_char]: Readed Buffer
        """
        oBuffer = create_string_buffer(size) # Setting the Buffer
        
        with open("/proc/{}/mem".format(self.process_id), 'rb+') as memory:
            memory.seek(address)
            memory.readinto(oBuffer)
            
        return oBuffer


# Function to Dump the Data
def dumper(output_path: str, process_handle: WindowsProcess | LinuxProcess, full_dump=False, mini_dump=False):
    with open(os.getcwd() + "/" + output_path, 'wb') as file:
        if full_dump:
            addresses = process_handle.get_memory_regions()
        elif mini_dump:
            if isinstance(process_handle, WindowsProcess):
                addresses = process_handle.get_memory_regions(private=True)
            else:
                addresses = process_handle.get_memory_regions(read_only=True)
        else:
            raise ArgumentError("Only can use one flag at time")
        
        for start, stop in addresses:
            RegionSize = stop - start
            try:
                buffer = process_handle.read_memory(start, RegionSize).raw
            except OSError:
                pass
            file.write(buffer)
        file.close()
        print(colored("[*] File dumped succesfully", "green"))


# Function to Get System OS
def get_os():
    return platform.system()


# Function to check if process exist
def process_checker(pid: int):
    """
    Check if given Process exist.

    Arguments:
        pid (int): The Process ID of the process to check.
    
    Returns:
        True if the process exist and False if it not exist.
    """
    for proc in psutil.process_iter():
        if proc.pid == pid:
            return True
    return False


# Function to Get PID by Process Name
def get_pid_by_name(process_name:str):
    for proc in psutil.process_iter():
        if proc.name() == process_name:
            if psutil.Process(proc.ppid()).name() == process_name:
                return proc.ppid()
            else:
                return proc.pid
    return None


# Main Function
def main():
    # Print Banner
    print(banner)
    
    # Description to Argparse
    msg = "Process Memory Dumper for Windows and Linux"
    
    # Initialize Argument Parser
    parser = argparse.ArgumentParser(description=msg)
    
    # Initialize Group Arguments
    group = parser.add_mutually_exclusive_group(required=True)
    
    # Initialize Flags Arguments
    flags_group = parser.add_argument_group(title="Dump Types")
    flags = flags_group.add_mutually_exclusive_group(required=True)
    
    # Adding Arguments
    parser.add_argument("-o",
                        "--output",
                        type=str,
                        help="Output file name where the dump will be saved.",
                        required=True)
    group.add_argument("-p", 
                        "--pid",
                        type=int,
                        help="Specify the Process ID to dump memory.")
    group.add_argument("-n", 
                        "--process-name",
                        type=str,
                        help="Specify the Process Name to dump memory.")
    flags.add_argument("-md",
                        action='store_true',
                        help="Create a Mini Dump of the process. Includes only the memory regions of type PRIVATE on Windows and only READABLE on Linux.")
    flags.add_argument("-fd", 
                        action='store_true',
                        help="Create a Full Dump of the process. Includes any type of memory: PRIVATE, IMAGE and MAPPED on Windows and PRIVATE and SHARED on Linux.")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    # Parse Args
    args = parser.parse_args()
    if args.pid:
        pid = args.pid
    else:
        pid = get_pid_by_name(args.process_name)

    # Define Variables
    output = args.output
    
    # Checks
    if not process_checker(pid) or pid is None:
        print(colored("! Process not exist", 'red'))
        sys.exit(1)
    
    if get_os() == 'Windows':
        process = WindowsProcess(pid)
        dumper(output, process, full_dump=args.fd, mini_dump=args.md)
    elif get_os() == 'Linux':
        process = LinuxProcess(pid)
        dumper(output, process, full_dump=args.fd, mini_dump=args.md)
    else:
        print(colored("! PyDump is not available for your OS Version", "red"))
        sys.exit(1)


if __name__ == '__main__':
    main()