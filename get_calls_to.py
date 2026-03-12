import idaapi
import ida_hexrays
import idautils
import ida_kernwin

# Ask for function name and find callers
input_str = ida_kernwin.ask_str("", 0, "Function name or address:")

if not input_str: 
    print("No input provided")

target = get_name_ea_simple(input_str)

if target == idaapi.BADADDR:
    try:
        target = idaapi.str2ea(input_str)
    except ValueError:
        print("Invalid function name or address.")


calls = set(idautils.CodeRefsTo(target, False))
count = len(calls)
if not calls:
    print("No calls found")
else:
    print(f"{count} calls to {target:X}")
    for call_ea in sorted(calls):
        # Get the function containing this call
        func = idaapi.get_func(call_ea)
        if not func:
            print("EA %08X: Not inside a function" % call_ea)
            continue
        
        # Decompile the containing function
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            print("EA %08X: Decompilation failed" % call_ea)
            continue
        
        # Find closest ctree item for this call_ea
        closest = cfunc.body.find_closest_addr(call_ea)
        if closest:
            x,y = cfunc.find_item_coords(closest)
            if y >= 0:
                pseudocode = cfunc.get_pseudocode()
                if y < len(pseudocode):
                    line_text = idaapi.tag_remove(pseudocode[y].line)
                    print("Call at %08X: %s" % (call_ea, line_text))
                else:
                    # Fallback to eamap if closest doesn't work
                    eamap = cfunc.get_eamap()
                    if call_ea in eamap:
                        lines = set()
                        for item in eamap[call_ea]:
                            line_idx = cfunc.get_line_by_item(item)
                            if line_idx >= 0:
                                clean_line = idaapi.tag_remove(cfunc.get_pseudocode()[line_idx].line)
                                lines.add(clean_line)
                        if lines:
                            print("Call at %08X:" % call_ea)
                            for ln in lines:
                                print("  " + ln)
                        else:
                            print("Call at %08X: No pseudocode line found" % call_ea)
                    else:
                        print("Call at %08X: No mapping found" % call_ea)
        else:
            print("Call at %08X: No closest item found" % call_ea)
