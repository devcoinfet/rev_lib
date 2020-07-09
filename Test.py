from ropper import RopperService
from pwn import *
import subprocess, re, sys


#I am learning this as I go and made the mistake doing a challenge following a tutorial for a 32 bit system and
#because I like to code I did that stuff first lol but hey i'm learning it all so no way i could have known anyhow ;)

def rop_32(binary_path):
     #locate pop pop ret calls 32 bit
     rop_gadgets = []
     # not all options need to be given
     options = {'color' : False,     # if gadgets are printed, use colored output: default: False
            'badbytes': '00',   # bad bytes which should not be in addresses or ropchains; default: ''
            'all' : False,      # Show all gadgets, this means to not remove double gadgets; default: False
            'inst_count' : 6,   # Number of instructions in a gadget; default: 6
            'type' : 'all',     # rop, jop, sys, all; default: all
            'detailed' : False} # if gadgets are printed, use detailed output; default: False

     rs = RopperService(options)

     ##### change options ######
     rs.options.color = True
     rs.options.badbytes = '00'
     rs.options.badbytes = ''
     rs.options.all = True


     ##### open binaries ######

     # it is possible to open multiple files
     rs.addFile(sys.argv[1], bytes=open(binary_path,'rb').read(), raw=True, arch='x86_64')



     rs.loadGadgetsFor()
     #rs.printGadgetsFor() # print all gadgets

     pprs = rs.searchPopPopRet()        # looks for ppr in all opened files
     for file, ppr in pprs.items():
         for p in ppr:
             print(p)
             rop_gadgets.append(p)


     return rop_gadgets
      
	  
				

	
	
def rop_gadget_locater_sh_32(program_file):
    remove_identifier = """Memory bytes information
======================================================="""
    cmd = ["ROPgadget", "--binary",sys.argv[1],"--memstr","\"sh\""]
    print("\nRunning command: "+' '.join(cmd))
    sp = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ""
    clean_s = ""
    clean_h = ""
    while True:
        out = sp.stdout.read(1).decode('utf-8')
        if out == '' and sp.poll() != None:
           break
        if out != '':
           output += out
           clean_rop = output.replace(remove_identifier,"")
           clean_rop2 = clean_rop.strip()
	   
    
    clean_rop2 = re.split(':',clean_rop)
    for item in clean_rop2:
        if "s"  in item:
           clean_s = item.strip()
           clean_s_2 = clean_s.replace("'s'","")

    for item in clean_rop2:
        if "h"  in item:
           clean_h = item.strip()
           clean_h_2 = clean_h.replace("'h'","")

    #print(clean_s_2.strip(),clean_h_2.strip())
    return clean_s_2.strip(),clean_h_2.strip()




def bss_overwrite_find_32(program_file):
    #we will use strcpy to write string in .bss address but what address ?
    output = subprocess.check_output("readelf -t "+sys.argv[1]+ "|grep  .bss -A 2", shell=True)
    result = output.split()
    return result[4]
    
 
def pop_pop_ret_32(program_file):
    #this is for strcpy
    output = subprocess.check_output("ROPgadget --binary "+sys.argv[1]+" --ropchain | grep pop | grep pop")
    result = output.split()
	  
def main():  
    writable_section_bss = bss_overwrite_find_32(sys.argv[1]) #locate writable section of .bss
    print("writable .bss Segment: "+str(writable_section_bss))			
    s,h = rop_gadget_locater_sh_32(sys.argv[1]) # locate bin/sh  strings in memory
    print("s->register:"+str(s),"h->register:"+str(h))

main()
