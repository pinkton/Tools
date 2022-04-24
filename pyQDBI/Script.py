import logging, os
os.add_dll_directory("C:/Program Files/QBDI 0.9.0")
import pyqbdi

logging.basicConfig(level=logging.INFO) #Prints all info and above
logging.info("[+] Gotcha")

vm = pyqbdi.VM()