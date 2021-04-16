#Applies String based Function IDs (SFID) to the opened program
#@author 
#@category FunctionID
#@keybinding 
#@menupath 
#@toolbar 



from ghidra.program.util import DefinedDataIterator
from ghidra.program.model.data import StringDataInstance
#TODO: do I need this?

from ghidra.program.model.symbol import RefType

from ghidra.program.model.symbol import SourceType
import json

MAX_ITER = 5
def get_all_functions(program):
	fun_manager = program.getFunctionManager()
	return fun_manager.getFunctions(True)

def read_sig_base():
	sig_file = askFile("Select signatures you want to apply", "OK")
	with open(sig_file.getAbsolutePath(), "r") as f:
		sigs = json.load(f)
	return sigs

def get_referenced_strings_per_function(program):
	referenced_strings_per_function = {}
	for data in DefinedDataIterator.definedStrings(program, None):
		if monitor.isCancelled():
			break
		data_str = StringDataInstance.getStringDataInstance(data)
		str_val = data_str.getStringValue()
		xrefs = getReferencesTo(data_str.getAddress())
		if len(xrefs) > 0:
			for xref in xrefs:
				addr = xref.getFromAddress()
				fun = getFunctionContaining(addr)
				if fun != None:
					fun_addr = str(fun.getEntryPoint())
					if fun_addr in referenced_strings_per_function:
						referenced_strings_per_function[fun_addr].append(str_val)
					else:
						referenced_strings_per_function[fun_addr] = [str_val]
	return referenced_strings_per_function

def add_reference_to_sig_list(sig_list, ref, string):
	addr = ref.getFromAddress()
	fun = getFunctionContaining(addr)

	if (fun != None):
		entry_addr_string = str(fun.getEntryPoint())
		
		if not (entry_addr_string in sig_list):
			sig_list[entry_addr_string] = [string]
		else:
			sig_list[entry_addr_string].append(string)
	
def add_multiple_references_to_sig_list(sig_list, refs, referenced_string):
	if len(refs) > 0 :
		for ref in refs:
			if monitor.isCancelled():
				break
			add_reference_to_sig_list(sig_list, ref, referenced_string)
	
def get_referenced_function_names_per_function(program):
	sig_list = {}
	for fun in get_all_functions(program):
		if monitor.isCancelled():
			break
		refs = getReferencesTo(fun.getEntryPoint())

		add_multiple_references_to_sig_list(sig_list, refs, fun.getName())
	return sig_list
	

def list_sim(str_list1, str_list2):
	match = 0
	for s1 in str_list1:
		if str_list1.count(s1) == str_list2.count(s1):
			match += 1
	for s2 in str_list2:
		if str_list1.count(s2) == str_list2.count(s2):
			match += 1
	similarity = float(match)/(len(str_list1) + len(str_list2))
	return similarity

def fuzzy_match(str_list1, str_list2, sim_threshold):
	threshold = 2*MAX_ITER*sim_threshold
	
	if (len(str_list1) < threshold or len(str_list2) < threshold):
		return strict_match(str_list1, str_list2)
	if list_sim(str_list1, str_list2) >= sim_threshold:
		return True
	return False
	
def strict_match(list1, list2):
	if(len(list1) < 10 ):
		return False
	if len(list1) != len(list2):
	 	return False
	for elem in list1 + list2:
		if(monitor.isCancelled()):
			print("aborting...")
			break
		if list1.count(elem) != list2.count(elem):
			return False
	return True

def read_sig_base():
	filename = askFile("select signature file", "OK").getAbsolutePath()
	with open(filename, "r") as f:
		sigs = json.load(f)
	return sigs

def get_addr_from_string(addr_string):
	try:
		addr = getAddressFactory().getAddress(str(addr_string))
	except:
		print(addr_string)
		quit()
	return addr

def apply_sigs(sig_base, current_program_sigs, iteration):
	rename_count = 0
	match_count = 0
	false_pos = 0
	print("Iteration: " + str(iteration))
	for funname in sig_base:
		if monitor.isCancelled():
			print("aborting...")
			break
		if funname.startswith("FUN_"):
			#ghidra generic function name in sigbase; no need to rename
			continue
		for addr_string in current_program_sigs:
			if monitor.isCancelled():
				print("aborting...")
				break
			addr = get_addr_from_string(addr_string)
			# first iteration only exact matches
			if fuzzy_match(sig_base[funname], current_program_sigs[addr_string], 1-(iteration/float(2*MAX_ITER))):
				match_count += 1
				fun = getFunctionAt(addr)
				if fun.getName() != funname:
					false_pos += 1
				if fun.getName().startswith("FUN_"):
					#only overwrite ghidra generic function names
					fun.setComment("Renamed by symbol based function matching")
					print("renaming " + str(fun.getName()))
					fun.setName(funname, SourceType.ANALYSIS)
					rename_count += 1
				else:
					fun.setComment("SymFID did not rename but has suggestion: "
					 + funname)
	print("matched: " + str(match_count))
	print("renamed: " + str(rename_count))

def main():
	sig_list_strings = get_referenced_strings_per_function(currentProgram)
	sig_list_fun_names = get_referenced_function_names_per_function(currentProgram)
	sigs = read_sig_base()
	for i in range(MAX_ITER):
		apply_sigs(sigs["strings"], sig_list_strings, i)
	for i in range(MAX_ITER):
		apply_sigs(sigs["functions"], sig_list_fun_names, i)
		

def rename_references_in_all_functions(current_program_sigs, sigs):
	for addr_string in current_program_sigs:
		if not addr_string.startswith("FUN_"):
			#If we don't know the name of the current function
			# we cannot use it to deduce the names of the called functions
			# within in
			addr = get_addr_from_string(addr_string)
			f = getFunctionContaining(addr)
			rename_references_in_function(f, sigs)

def rename_references_in_function(function, sigs):
	#TODO creating new objects every time is inefficient
	program = function.getProgram()
	refMgr = program.getReferenceManager();
	for fromAddr in refMgr.getReferenceSourceIterator(function.getBody(), True):
		for ref in refMgr.getReferencesFrom(fromAddr):
			call_num = 0
			if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
				#TODO can't do it this way because source iterator does not give
				# the references in a paricular order
				addr = ref.getToAddress()
				referenced_function = getFunctionContaining(addr)
				if function.getName() in sigs:
					print(referenced_function.getName() + " might be " + str(sigs[function.getName()][call_num]))
					print("because it is called in " + function.getName() + " with params " + str(referenced_function.getParameters()))
				call_num += 1
			if ref.getReferenceType() == RefType.READ:
				pass
			if ref.getReferenceType() == RefType.WRITE:
				pass

	
if __name__ == "__main__":
	main()
	
	

