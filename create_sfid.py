#creates function signatures for all functions of the current program.
#@author 
#@category FunctionID
#@keybinding 
#@menupath 
#@toolbar 


from ghidra.program.util import DefinedDataIterator
from ghidra.program.model.data import StringDataInstance

import json



def get_all_functions():
	fun_manager = currentProgram.getFunctionManager()
	return fun_manager.getFunctions(True)
	
def add_reference_to_sig_list(sig_list, ref, string):
	addr = ref.getFromAddress()
	fun = getFunctionContaining(addr)
	
	if (fun != None):
		if not (fun.getName() in sig_list):
			sig_list[fun.getName()] = [string]
		else:
			sig_list[fun.getName()].append(string)
			
def add_multiple_references_to_sig_list(sig_list, refs, referenced_string):
	if len(refs) > 0 :
		for ref in refs:
			if monitor.isCancelled():
				break
			add_reference_to_sig_list(sig_list, ref, referenced_string)
			
def build_signature_list_for_strings():
	sig_list = {}
	for data in DefinedDataIterator.definedStrings(currentProgram, None):
		if(monitor.isCancelled()):
			break
		dataStr = StringDataInstance.getStringDataInstance(data)
		string_val = dataStr.getStringValue()
		references = getReferencesTo(dataStr.getAddress())
		
		add_multiple_references_to_sig_list(sig_list, references, string_val)
	return sig_list
		
def build_signature_list_for_fun_names():
	sig_list = {}
	for fun in get_all_functions():
		if monitor.isCancelled():
			break
		refs = getReferencesTo(fun.getEntryPoint())
		add_multiple_references_to_sig_list(sig_list, refs, fun.getName())
	return sig_list
		
def write_sigs_to_json_file(sigs, filename):
	with open(filename, "w") as f:
		json.dump(sigs, f)

def build_signatures_for_current_program():
	referenced_strings_per_function = build_signature_list_for_strings()
	referenced_function_names_per_function = build_signature_list_for_fun_names()
	sigs = {
		"strings" : referenced_strings_per_function,
		"functions" : referenced_function_names_per_function
	}
	return sigs
	
def load_sigs(filename):
	with open(filename, "r") as f:
		sigs = json.load(f)
	return sigs

def main():
	sigs = build_signatures_for_current_program()
	args = getScriptArgs()
	if len(args) > 0:
		filename = args[0]
	else:
		filename = askFile("Choose file to save signatures", "OK").getAbsolutePath()
	old_sigs = load_sigs(filename)
	print("reading old sigs...")
	print(old_sigs)
	old_sigs["functions"].update(sigs["functions"])
	old_sigs["strings"].update(sigs["functions"])
	print("new sigs are:")
	print(sigs)
	print("updating sigs...")
	print("sigs are now:")
	print(old_sigs)
	write_sigs_to_json_file(old_sigs, filename)
		
if __name__ == "__main__":
	main()

	
