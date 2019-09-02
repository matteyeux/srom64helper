import idautils
import idaapi
import idc
import struct

def find_panic(base_ea):
	pk_ea = ida_search.find_text(base_ea, 1, 1, "double panic in ", ida_search.SEARCH_DOWN)

	if pk_ea != 0xffffffffffffffff:
		for xref in idautils.XrefsTo(pk_ea):
			func = idaapi.get_func(xref.frm)
			print "\t[+] _panic = 0x%x" % (func.startEA)
			idc.MakeName(func.startEA, "_panic")
			return func.startEA

	return 0xffffffffffffffff

def find_do_printf(base_ea):
	pk_ea = ida_search.find_text(base_ea, 1, 1, "<ptr>", ida_search.SEARCH_DOWN)

	if pk_ea != 0xffffffffffffffff:
		for xref in idautils.XrefsTo(pk_ea):
			func = idaapi.get_func(xref.frm)
			print "\t[+] _do_printf = 0x%x" % (func.startEA)
			idc.MakeName(func.startEA, "_do_printf")
			return func.startEA

	return 0xffffffffffffffff

# for the moment this function does not work, 
# It seems like idaapi.get_func(xref.frm) returns None

# C:\Program Files\IDA 7.0\loaders\srom64helper.py: Traceback (most recent call last):
#   File "C:/Program Files/IDA 7.0/loaders/srom64helper.py", line 137, in load_file
# 	find_platform_get_usb_product_id(segment_start)
#   File "C:/Program Files/IDA 7.0/loaders/srom64helper.py", line 49, in find_platform_get_usb_product_id
# 	idc.MakeName(func.startEA, "_platform_get_usb_product_id")
# AttributeError: 'NoneType' object has no attribute 'startEA'

def find_platform_get_usb_product_id(base_ea):
	pk_ea = ida_search.find_text(base_ea, 1, 1, "Apple Mobile Device (DFU Mode)", ida_search.SEARCH_DOWN)

	if pk_ea != 0xffffffffffffffff:
		for xref in idautils.XrefsTo(pk_ea):
			func = idaapi.get_func(xref.frm)
			print "\t[+] _platform_get_usb_product_id = 0x%x" % (func.startEA)
			idc.MakeName(func.startEA, "_platform_get_usb_product_id")
			return func.startEA

	return 0xffffffffffffffff

def accept_file(fd, fname):
	ret = 0

	if type(fname) == str:
		fd.seek(0x200)
		ver_str = fd.read(0x20)

		if ver_str[:9] == "SecureROM":
			ret = {"format" : "SecureROM (AArch64)", "processor" : "arm"}

	return ret

def load_file(fd, neflags, format):
	size = 0
	base_addr = 0
	ea = 0

	idaapi.set_processor_type("arm", idaapi.SETPROC_ALL)
	idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT
	
	if (neflags & idaapi.NEF_RELOAD) != 0:
		return 1

	fd.seek(0, idaapi.SEEK_END)
	size = fd.tell()

	segm = idaapi.segment_t()
	segm.bitness = 2 # 64-bit
	segm.start_ea = 0
	segm.end_ea = size
	idaapi.add_segm_ex(segm, "SecureROM", "CODE", idaapi.ADDSEG_OR_DIE)

	fd.seek(0)
	fd.file2base(0, 0, size, False)

	idaapi.add_entry(0, 0, "start", 1)
	idc.MakeFunction(ea)

	print("[+] Marked as code")

	# heuristic
	while(True):
		mnemonic = idc.GetMnem(ea)
		
		if "LDR" in mnemonic:
			base_str = idc.GetOpnd(ea, 1)
			base_addr = int(base_str.split("=")[1], 16)
			
			break

		ea += 4

	print("[+] Rebasing to address 0x%x" % (base_addr))
	idaapi.rebase_program(base_addr, idc.MSF_NOFIX)
	idaapi.autoWait()


	segment_start = base_addr
	segment_end = idc.GetSegmentAttr(segment_start, idc.SEGATTR_END)

	ea = segment_start

	print("[+] Searching and defining functions")

	while ea != idc.BADADDR:
		ea = idc.FindBinary(ea, idc.SEARCH_DOWN, "BF A9", 16)
			
		if ea != idc.BADADDR:
			ea = ea - 2

			if (ea % 4) == 0 and idc.GetFlags(ea) < 0x200:
				idc.MakeFunction(ea)

			ea = ea + 4
	
	idc.AnalyzeArea(segment_start, segment_end)
	idaapi.autoWait()

	print("[+] Looking for interesting functions")
	find_panic(segment_start)
	find_do_printf(segment_start)
	# find_platform_get_usb_product_id(segment_start)
	return 1
