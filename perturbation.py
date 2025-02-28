import lief
import random
import sys
import os
import json
import array
import subprocess
import pefile
import r2pipe

module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
COMMON_SECTION_NAMES = open(os.path.join(
    module_path, 'section_names.txt'), 'r').read().rstrip().split('\n')
COMMON_IMPORTS = json.load(
    open(os.path.join(module_path, 'small_dll_imports.json'), 'r'))
ELF_COMMON_IMPORTS = json.load(
    open(os.path.join(module_path, 'elf_dll_imports.json'), 'r'))
STUB_FILE = ""#"hello_lief.bin"
STUB = ""#lief.parse(os.path.join(module_path, STUB_FILE))
lief.logging.disable()

def lastindex(bytelist):
    for i in range(len(bytelist) - 1, 0, -1):
        if bytelist[i] != 0:
            return i + 1
    return -1

def fparsed_to_bytes(fparsed, im=False):
    builder = lief.PE.Builder(fparsed)
    if im:
        builder.build_imports(True)
        builder.patch_imports(True)
    builder.build()
    return array.array('B', builder.get_build()).tobytes()

def elf_fparsed_to_bytes(fparsed, im=False):
    builder = lief.ELF.Builder(fparsed)
    if im:
        builder.build_imports(True)
        builder.patch_imports(True)
    builder.build()
    return array.array('B', builder.get_build()).tobytes()

# success
def overlay_append(fbytes, seed=None):
    random.seed(seed)
    l = 2 ** random.randint(5, 8)
    upper = random.randrange(128)
    new_fbytes = fbytes + bytes([random.randint(0, upper) for _ in range(l)])
    new_fparsed = lief.parse(new_fbytes)
    return fparsed_to_bytes(new_fparsed)

def elf_overlay_append(fbytes, seed=None):
    random.seed(seed)
    l = 2 ** random.randint(5, 8)
    upper = random.randrange(128)
    new_fbytes = fbytes + bytes([random.randint(0, upper) for _ in range(l)])
    new_fparsed = lief.parse(new_fbytes)

    try:
        return elf_fparsed_to_bytes(new_fparsed)
    except:
        return fbytes

    # return elf_fparsed_to_bytes(new_fparsed)


def imports_append(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    libname = random.choice(list(COMMON_IMPORTS.keys()))
    funcname = random.choice(list(COMMON_IMPORTS[libname]))
    lowerlibname = libname.lower()

    lib = None

    for im in fparsed.imports:
        if im.name.lower() == lowerlibname:
            lib = im
            break
    if lib is None:
        lib = fparsed.add_library(libname)

    names = set([e.name for e in lib.entries])
    if not funcname in names:
        lib.add_entry(funcname)

    return fparsed_to_bytes(fparsed, im=True)

def elf_imports_append(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)

    while True:
        libname = random.choice(list(ELF_COMMON_IMPORTS.keys()))
        if libname not in fparsed.libraries:
            fparsed.add_library(libname)
            break

    try:
        return elf_fparsed_to_bytes(fparsed)
    except:
        return fbytes

    # return elf_fparsed_to_bytes(fparsed)

# mostly failed
def section_add(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    length = random.randrange(1, 6)
    new_section = lief.PE.Section("." + "".join(random.sample([chr(i) for i in range(97, 123)], length)))

    # fill with random content
    upper = random.randrange(128)  # it was 256
    L = 2 ** random.randint(5, 8)
    size = fparsed.optional_header.section_alignment
    new_section.content = [random.randint(0, upper) for _ in range(L)]

    new_section.virtual_size = size

    new_section.virtual_address = max(
        [s.virtual_address + s.virtual_size for s in fparsed.sections])
    # add a new empty section

    fparsed.add_section(new_section,
                        random.choice([
                            lief.PE.SECTION_TYPES.BSS,
                            lief.PE.SECTION_TYPES.DATA,
                            lief.PE.SECTION_TYPES.EXPORT,
                            lief.PE.SECTION_TYPES.IDATA,
                            lief.PE.SECTION_TYPES.RELOCATION,
                            lief.PE.SECTION_TYPES.RESOURCE,
                            lief.PE.SECTION_TYPES.TEXT,
                            lief.PE.SECTION_TYPES.TLS_,
                            lief.PE.SECTION_TYPES.UNKNOWN,
                        ]))

    return fparsed_to_bytes(fparsed)

def elf_section_add(fbytes, seed=None):
    fparsed = lief.parse(fbytes)
    length = random.randrange(1, 6)
    upper = random.randrange(128)
    L = 2 ** random.randint(5, 8)
    new_section = lief.ELF.Section("." + "".join(random.sample([chr(i) for i in range(97, 123)], length)))
    new_section.type = random.choice(
        [lief.ELF.SECTION_TYPES.NULL, lief.ELF.SECTION_TYPES.PROGBITS, lief.ELF.SECTION_TYPES.SYMTAB,
         lief.ELF.SECTION_TYPES.STRTAB,
         lief.ELF.SECTION_TYPES.RELA, lief.ELF.SECTION_TYPES.HASH, lief.ELF.SECTION_TYPES.DYNAMIC,
         lief.ELF.SECTION_TYPES.NOTE,
         lief.ELF.SECTION_TYPES.NOBITS, lief.ELF.SECTION_TYPES.REL, lief.ELF.SECTION_TYPES.SHLIB,
         lief.ELF.SECTION_TYPES.DYNSYM,
         lief.ELF.SECTION_TYPES.INIT_ARRAY, lief.ELF.SECTION_TYPES.FINI_ARRAY, lief.ELF.SECTION_TYPES.PREINIT_ARRAY,
         lief.ELF.SECTION_TYPES.GROUP,
         lief.ELF.SECTION_TYPES.SYMTAB_SHNDX, lief.ELF.SECTION_TYPES.LOOS, lief.ELF.SECTION_TYPES.GNU_ATTRIBUTES,
         lief.ELF.SECTION_TYPES.GNU_HASH,
         lief.ELF.SECTION_TYPES.GNU_VERDEF, lief.ELF.SECTION_TYPES.GNU_VERNEED, lief.ELF.SECTION_TYPES.HIOS,
         lief.ELF.SECTION_TYPES.ANDROID_REL,
         lief.ELF.SECTION_TYPES.ANDROID_RELA, lief.ELF.SECTION_TYPES.LLVM_ADDRSIG, lief.ELF.SECTION_TYPES.RELR,
         lief.ELF.SECTION_TYPES.ARM_EXIDX,
         lief.ELF.SECTION_TYPES.ARM_PREEMPTMAP, lief.ELF.SECTION_TYPES.ARM_ATTRIBUTES,
         lief.ELF.SECTION_TYPES.ARM_DEBUGOVERLAY, lief.ELF.SECTION_TYPES.ARM_OVERLAYSECTION,
         lief.ELF.SECTION_TYPES.LOPROC, lief.ELF.SECTION_TYPES.X86_64_UNWIND, lief.ELF.SECTION_TYPES.HIPROC,
         lief.ELF.SECTION_TYPES.LOUSER, lief.ELF.SECTION_TYPES.HIUSER])
    new_section.content = [random.randint(0, upper) for _ in range(L)]
    new_section.alignment = 8
    fparsed.add(new_section, False)
    try:
        return elf_fparsed_to_bytes(fparsed)
    except:
        return fbytes


    # return elf_fparsed_to_bytes(fparsed)

def section_append_(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    targeted_section = random.choice(fparsed.sections)
    L = 2 ** random.randint(5, 8)
    available_size = targeted_section.size - len(targeted_section.content)

    if targeted_section.virtual_size <= targeted_section.size:
        targeted_section.virtual_size = targeted_section.size
    else:
        targeted_section.size = (int(targeted_section.virtual_size / 512) + 1) * 512

    # print (targeted_section.name)

    if L > available_size:
        L = available_size

    upper = random.randrange(128)  # it was 256
    temp = list(targeted_section.content)
    temp.append(1)
    # temp = temp + [random.randint(0, upper) for _ in range(L)]
    targeted_section.content = temp

    return fparsed
# fail
def section_append(fbytes, seed=None):
    return fparsed_to_bytes(section_append_(fbytes, seed))

def elf_section_append(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    targeted_section = random.choice(fparsed.sections)
    L = 2 ** random.randint(5, 8)
    available_size = targeted_section.size - len(targeted_section.content)

    if targeted_section.original_size <= targeted_section.size:
        targeted_section.size = targeted_section.original_size
    else:
        targeted_section.size = (int(targeted_section.original_size / 512) + 1) * 512

    # print (targeted_section.name)

    if L > available_size:
        L = available_size

    upper = random.randrange(128)  # it was 256
    temp = list(targeted_section.content)
    temp.append(1)
    # temp = temp + [random.randint(0, upper) for _ in range(L)]
    targeted_section.content = temp

    return elf_fparsed_to_bytes(fparsed)

def upx_pack(fbytes, seed=None):
    # tested with UPX 3.91
    global nfbytes
    nfbytes = bytes(fbytes)

    random.seed(seed)
    tmpfilename = os.getcwd() + "/sample/upx/origin"
    # tmpfilename = os.path.join(
    # tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

    # dump bytez to a temporary file
    with open(tmpfilename, 'wb') as outfile:
        outfile.write(fbytes)

    options = ['--force', '--overlay=copy']
    compression_level = random.randint(1, 9)
    options += ['-{}'.format(compression_level)]

    options += ['--compress-exports={}'.format(random.randint(0, 1))]
    options += ['--compress-icons={}'.format(random.randint(0, 3))]
    options += ['--compress-resources={}'.format(random.randint(0, 1))]
    options += ['--strip-relocs={}'.format(random.randint(0, 1))]

    with open(os.devnull, 'w') as DEVNULL:
        retcode = subprocess.call(
            ['upx-ucl'] + options + [tmpfilename, '-o', tmpfilename.replace("origin", "origin_packed")], stdout=DEVNULL,
            stderr=DEVNULL)

    os.unlink(tmpfilename)

    if retcode == 0:  # successfully packed

        with open(tmpfilename.replace("origin", "origin_packed"), 'rb') as infile:
            nfbytes = infile.read()

        os.unlink(tmpfilename.replace("origin", "origin_packed"))

    # fparsed = lief.parse(nfbytes)

    return nfbytes

def elf_upx_pack(fbytes, seed=None):
    return upx_pack(fbytes, seed)

def upx_unpack(fbytes, seed=None):
    # dump bytez to a temporary file
    global nfbytes
    nfbytes = bytes(fbytes)

    tmpfilename = os.getcwd() + "/sample/upx/origin"
    # tmpfilename = os.path.join(
    #    tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

    with open(tmpfilename, 'wb') as outfile:
        outfile.write(fbytes)

    with open(os.devnull, 'w') as DEVNULL:
        retcode = subprocess.call(
            ['upx-ucl', tmpfilename, '-d', '-o', tmpfilename.replace("origin", "origin_unpacked")], stdout=DEVNULL,
            stderr=DEVNULL)

    os.unlink(tmpfilename)

    if retcode == 0:  # successfully unpacked
        with open(tmpfilename.replace("origin", "origin_unpacked"), 'rb') as result:
            nfbytes = result.read()

        os.unlink(tmpfilename.replace("origin", "origin_unpacked"))

    # fparsed = lief.parse(nfbytes)

    return nfbytes  # fparsed_to_bytes(fparsed)

def elf_upx_unpack(fbytes, seed=None):
    return upx_unpack(fbytes, seed)

def remove_signature(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)

    if fparsed.has_signature:
        for i, e in enumerate(fparsed.data_directories):
            if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
                break
        if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
            # remove signature from certificate table
            e.rva = 0
            e.size = 0

    return fparsed_to_bytes(fparsed)


def remove_debug(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)

    if fparsed.has_debug:
        for i, e in enumerate(fparsed.data_directories):
            if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
                break
        if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
            # remove signature from certificate table
            e.rva = 0
            e.size = 0

    return fparsed_to_bytes(fparsed)


def break_optional_header_checksum(fbytes, seed=None):
    fparsed = lief.parse(fbytes)
    fparsed.optional_header.checksum = 0

    return fparsed_to_bytes(fparsed)


def inject_random_codecave_(fbytes):
    fparsed = lief.parse(fbytes)
    random.seed(None)

    if len(fparsed.sections) > 0:
        for sec in fparsed.sections:
            tsection = random.choice(fparsed.sections)
            if len(tsection.content) != 0:
                break
        # print (target)
        start_index = lastindex(tsection.content)
        content = list(tsection.content)
        content_len = len(content)
        # pert_s = random.randrange(0,content_len-start_index)
        for i in range(start_index + 10, start_index + 20):
            if i >= content_len:
                break
            content[i] = random.randrange(0, 256)
        tsection.content = content
    return fparsed
# success
def inject_random_codecave(fbytes):
    return fparsed_to_bytes(inject_random_codecave_(fbytes))

def elf_inject_random_codecave(fbytes):
    try:
        return elf_fparsed_to_bytes(inject_random_codecave_(fbytes))
    except:
        return fbytes

    # return elf_fparsed_to_bytes(inject_random_codecave_(fbytes))

def section_rename_(fbytes):
    random.seed(None)
    length = random.randrange(1, 6)
    fparsed = lief.parse(fbytes)
    name = "." + ''.join(random.sample([chr(i) for i in range(97, 123)], length))

    if len(fparsed.sections) > 0:
        targeted_section = random.choice(fparsed.sections)
        targeted_section.name = name
    return fparsed

# success
def section_rename(fbytes):
    return fparsed_to_bytes(section_rename_(fbytes))

def elf_section_rename(fbytes):
    try:
        return elf_fparsed_to_bytes(section_rename_(fbytes))
    except:
        return fbytes
    # return elf_fparsed_to_bytes(section_rename_(fbytes))

# success
def pert_dos_stub(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)
    dos_stub_info = list(fparsed.dos_stub)
    sindex, eindex = tuple(sorted(random.sample([i for i in range(len(dos_stub_info))], 2)))

    for i in range(sindex, eindex):
        dos_stub_info[i] = random.randrange(0, 256)

    fparsed.dos_stub = dos_stub_info
    return fparsed_to_bytes(fparsed)

def pert_bin_name_(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)
    length = random.randrange(1, 8)
    name = ''.join(random.sample([chr(i) for i in range(97, 123)], length))
    fparsed.name = name
    return fparsed

# success
def pert_bin_name(fbytes):
    return fparsed_to_bytes(pert_bin_name_(fbytes))

def elf_pert_bin_name(fbytes):
    return elf_fparsed_to_bytes(pert_bin_name_(fbytes))

# partially success
def pert_optional_header_dllchlist(fbytes):
    fparsed = lief.parse(fbytes)
    chlist = [lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA,
              lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE,
              lief.PE.DLL_CHARACTERISTICS.FORCE_INTEGRITY,
              lief.PE.DLL_CHARACTERISTICS.NX_COMPAT,
              lief.PE.DLL_CHARACTERISTICS.NO_ISOLATION,
              lief.PE.DLL_CHARACTERISTICS.NO_SEH,
              lief.PE.DLL_CHARACTERISTICS.NO_BIND,
              lief.PE.DLL_CHARACTERISTICS.APPCONTAINER,
              lief.PE.DLL_CHARACTERISTICS.WDM_DRIVER,
              lief.PE.DLL_CHARACTERISTICS.GUARD_CF,
              lief.PE.DLL_CHARACTERISTICS.TERMINAL_SERVER_AWARE]

    #print(fparsed)
    fparsed.optional_header.add(chlist[0])

    return fparsed_to_bytes(fparsed)


# success
def pert_optional_header_dllch(fbytes):
    fparsed = lief.parse(fbytes)

    fparsed.optional_header.dll_characteristics = random.randrange(0, 3000)
    # fparsed.optional_header. 
    return fparsed_to_bytes(fparsed)


# success
def pert_rich_header(fbytes):  # add rich header entry
    fparsed = lief.parse(fbytes)
    new_entry = lief.PE.RichEntry()
    new_entry.id = 101
    new_entry.build_id = 0x766f
    new_entry.count = 2

    fparsed.rich_header.add_entry(new_entry)

    return fparsed_to_bytes(fparsed)


# success
def pert_dos_header(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)

    fparsed.dos_header.initial_ip = random.randint(0, 8)
    fparsed.dos_header.initial_relative_ss = random.randint(0, 8)
    fparsed.dos_header.overlay_number = random.randint(0, 8)
    fparsed.dos_header.oem_id = random.randint(0, 8)
    fparsed.dos_header.oem_info = random.randint(0, 8)

    return fparsed_to_bytes(fparsed)


def pert_optional_header(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)

    temp1 = [fparsed.optional_header.sizeof_uninitialized_data,
             fparsed.optional_header.sizeof_initialized_data,
             fparsed.optional_header.baseof_code,
             fparsed.optional_header.checksum,
             fparsed.optional_header.sizeof_heap_reserve,
             fparsed.optional_header.sizeof_stack_commit,
             fparsed.optional_header.win32_version_value,

             fparsed.optional_header.major_linker_version,
             fparsed.optional_header.major_image_version,
             fparsed.optional_header.major_operating_system_version,
             fparsed.optional_header.major_subsystem_version,
             fparsed.optional_header.minor_image_version,
             fparsed.optional_header.minor_linker_version,
             fparsed.optional_header.minor_operating_system_version,
             fparsed.optional_header.minor_subsystem_version]

    idx = random.randrange(len(temp1))
    if idx < 6:
        temp1[idx] = random.randrange(0, 2 ** 32)
    else:
        temp1[idx] = random.randrange(0, 2 ** 8)

    # fparsed.optional_header.sizeof_stack_reserve =random.randrange(0,2**31)
    # fparsed.optional_header.numberof_rva_and_size = random.randrange(0,2**31)

    return fparsed_to_bytes(fparsed)


def pert_coff_header(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)

    fparsed.header.numberof_symbols = random.randrange(0, 2 ** 32)
    fparsed.header.time_date_stamps = random.randrange(0, 2 ** 32)
    fparsed.header.pointerto_symbol_table = random.randrange(0, 2 ** 32)

    return fparsed_to_bytes(fparsed)


def pert_data_directory(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)

    target = random.choice(fparsed.data_directories)

    target.rva = random.randrange(0, 2 ** 32)
    target.size = random.randrange(0, 2 ** 32)

    return fparsed_to_bytes(fparsed)


def elf_segment_add(fbytes, seed=None):
    fparsed = lief.parse(fbytes)

    length = random.randrange(1, 6)
    upper = random.randrange(128)
    L = 2 ** random.randint(5, 8)
    new_segment = lief.ELF.Segment()

    new_segment.add(random.choice([lief.ELF.SEGMENT_FLAGS.NONE,
                                   lief.ELF.SEGMENT_FLAGS.X, lief.ELF.SEGMENT_FLAGS.W, lief.ELF.SEGMENT_FLAGS.R]))
    new_segment.type = random.choice([lief.ELF.SEGMENT_TYPES.NULL, lief.ELF.SEGMENT_TYPES.LOAD, lief.ELF.SEGMENT_TYPES.DYNAMIC, lief.ELF.SEGMENT_TYPES.INTERP,
    lief.ELF.SEGMENT_TYPES.NOTE, lief.ELF.SEGMENT_TYPES.SHLIB, lief.ELF.SEGMENT_TYPES.PHDR, lief.ELF.SEGMENT_TYPES.TLS,
    lief.ELF.SEGMENT_TYPES.GNU_EH_FRAME, lief.ELF.SEGMENT_TYPES.GNU_PROPERTY, lief.ELF.SEGMENT_TYPES.GNU_STACK, lief.ELF.SEGMENT_TYPES.GNU_RELRO,
    lief.ELF.SEGMENT_TYPES.ARM_ARCHEXT, lief.ELF.SEGMENT_TYPES.ARM_UNWIND, lief.ELF.SEGMENT_TYPES.UNWIND])
    new_segment.content = [random.randint(0, upper) for _ in range(L)]
    # new_segment.alignment = 0
    fparsed.add(new_segment)

    try:
        return elf_fparsed_to_bytes(fparsed)
    except:
        return fbytes


def elf_program_header_table(fbytes, seed=None):
    random.seed(seed)
    liefparsed = lief.parse(fbytes)

    # do not perturb if not executable
    if str(liefparsed.header.file_type) == 'E_TYPE.EXECUTABLE':
        return fbytes

    builder = lief.ELF.Builder(liefparsed)
    builder.build()
    builder.write('/home/infobeyond/workspace/VirusShare/testElf/phtpert')

    PHT_Offset = liefparsed.header.program_header_offset
    pert_PHT_SN = random.randrange(0, liefparsed.header.numberof_segments)
    print(liefparsed.get_content_from_virtual_address(PHT_Offset,
                                                      liefparsed.header.numberof_segments * liefparsed.header.program_header_size))
    pertAddress = liefparsed.offset_to_virtual_address(PHT_Offset + (pert_PHT_SN * liefparsed.header.program_header_size))

    r2n = r2pipe.open('/home/infobeyond/workspace/VirusShare/testElf/phtpert', ['-2', '-n','-w'])
    for x in range(liefparsed.header.program_header_size):
        # leave p_offset(4-byte), p_vaddr(4-byte), and p_paddr(4-byte) unmodified
        if x >=4 and x<=16:
            continue
        # insert random codes
        r2n.cmd("s " + str(liefparsed.offset_to_virtual_address(pertAddress+x)))
        data = str(hex(random.randrange(0, 255)))
        print(data)
        r2n.cmd("wx " + data)

    print(pertAddress)
    liefparsed = lief.parse('/home/infobeyond/workspace/VirusShare/testElf/phtpert')
    builder = lief.ELF.Builder(liefparsed)
    builder.build()
    print(liefparsed.get_content_from_virtual_address(PHT_Offset,
                                                      liefparsed.header.numberof_segments * liefparsed.header.program_header_size))
    return array.array('B', builder.get_build()).tobytes()

def elf_segment_append(fbytes, seed=None):
    random.seed(seed)
    fparsed = lief.parse(fbytes)
    targeted_segment = random.choice(fparsed.segments)
    L = 2 ** random.randint(5, 8)
    available_size = targeted_segment.physical_size - len(targeted_segment.content)

    if targeted_segment.virtual_size <= targeted_segment.physical_size:
        targeted_segment.virtual_size = targeted_segment.physical_size
    else:
        targeted_segment.physical_size = (int(targeted_segment.virtual_size / 512) + 1) * 512

    # print (targeted_section.name)

    if L > available_size:
        L = available_size

    upper = random.randrange(128)  # it was 256
    temp = list(targeted_segment.content)
    temp.append(1)
    # temp = temp + [random.randint(0, upper) for _ in range(L)]
    targeted_segment.content = temp

    try:
        return elf_fparsed_to_bytes(fparsed)
    except:
        return fbytes
    # return elf_fparsed_to_bytes(fparsed)

def build_lief(fbytes, fname):
    fparsed = lief.parse(fbytes)
    builder = lief.PE.Builder(fparsed)
    builder.build()
    ####new_fname = fname.replace(".exe", "_m.exe")
    new_fname = fname + "_m.exe"
    builder.write(new_fname)

def build_lief_name(fbytes, original_fname, new_fname):
    pe = pefile.PE(original_fname)
    fparsed = lief.parse(fbytes)
    builder = lief.PE.Builder(fparsed)
    # builder.build_imports(True)
    builder.build()
    #######new_fname = fname.replace(".exe", "_" + pertname + ".exe")
    #new_fname = fname + "_" + pertname
    builder.write(new_fname)

    pe2 = pefile.PE(new_fname)

    if pe.OPTIONAL_HEADER.SizeOfHeaders != pe2.OPTIONAL_HEADER.SizeOfHeaders:
        print('---------------------------------------------------------------------------------------------------------------------------------------------')
        pe2.OPTIONAL_HEADER.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders

    pe2.write(new_fname)