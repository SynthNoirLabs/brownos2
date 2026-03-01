with open("probe_llm_v11.py", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "from registry_globals import" in line:
        new_lines.append("from registry_globals import Var, Lam, App, encode_term\n")
        new_lines.append("NIL = Lam(Lam(Var(0)))\n")
    else:
        new_lines.append(line)

with open("probe_llm_v11.py", "w") as f:
    f.writelines(new_lines)
