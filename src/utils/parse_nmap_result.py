
def format_input(nmap_res: str) -> str:

    # Remove 'OS:' from each row
    nmap_res = nmap_res.replace('OS:', '')

    index = nmap_res.find("SEQ")
    if index != -1:
        nmap_res = nmap_res[index:]

    lines = nmap_res.splitlines()

    # Remove lines before "SEQ"
    filtered_lines = []
    start_adding = False
    for line in lines:
        if "SEQ" in line:
            start_adding = True
        if start_adding:
            filtered_lines.append(line)

    # Join lines
    formatted_nmap_res = ''.join(filtered_lines).replace(')', ')\n')
    return formatted_nmap_res


if __name__ == "__main__":
    # This is the output of: sudo nmap -sS -T4 -O -d nmap.scanme.org
    input_str = """OS:SCAN(V=7.95%E=4%D=12/7%OT=22%CT=1%CU=37843%PV=N%DS=23%DC=I%G=N%TM=67542A
    OS:34%P=arm-apple-darwin23.4.0)SEQ(SP=FD%GCD=1%ISR=110%TI=Z%II=I%TS=A)OPS(O
    OS:1=M5ACST11NW7%O2=M5ACST11NW7%O3=M5ACNNT11NW7%O4=M5ACST11NW7%O5=M5ACST11N
    OS:W7%O6=M5ACST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
    OS:=Y%DF=Y%T=43%W=FAF0%O=M5ACNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=42%S=O%A=S+%F=AS%
    OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=43%W=0%S=Z%A=S+%F=AR%O=%RD=0%
    OS:Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=42%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK
    OS:=G%RUD=G)IE(R=Y%DFI=N%T=42%CD=S)"""

    formatted_str = format_input(input_str)
    print("\n" + formatted_str)
