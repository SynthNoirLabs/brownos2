with open("probe_llm_v11.py", "r") as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    if "from registry_globals import" in line:
        new_lines.append("from registry_globals import Var, Lam, App, encode_term, NIL\n")
    elif line.startswith("def string_to_list") and "from solve_brownos_answer" not in lines[i+1]:
        pass
    else:
        new_lines.append(line)

with open("probe_llm_v11.py", "w") as f:
    f.writelines(new_lines)
