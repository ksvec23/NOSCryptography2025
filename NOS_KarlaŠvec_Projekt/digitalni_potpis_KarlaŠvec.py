import os
import base64
import hashlib

from tkinter import Tk
from tkinter import ttk
from tkinter import filedialog, messagebox, scrolledtext

from cryptography.fernet import Fernet  #za simetricno kriptiranje
from cryptography.hazmat.primitives.asymmetric import rsa, padding  #za asimetricno kriptiranje
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


#kreiranje GUI
class DigitalniPotpisGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Digitalni potpis - projekt iz kolegija Napredni operacijski sustavi")
        self.root.geometry("800x650")
        self.input_path=None
        self.setup_ui()
    
    def setup_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(sticky=('W', 'E', 'N', 'S'))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        ttk.Label(frm, text="Dobrodošli u aplikaciju za digitalne potpise!", font=("Arial", 16, "bold")).grid(column=0, row=0, columnspan=3, pady=10)

        ttk.Button(frm, text="Odaberite ulaznu datoteku", command=self.browse_file).grid(column=0, row=1, sticky='W')
        self.lbl_input=ttk.Label(frm, text="Nije odabrana datoteka", width=60)
        self.lbl_input.grid(column=1, row=1, columnspan=2, sticky='W')

        ttk.Button(frm, text="Generiraj ključeve", command=self.generiranje_i_spremanje_kljuceva).grid(column=0, row=2, pady=5, sticky='W')
        ttk.Button(frm, text="Simetrično kriptiranje", command=self.simetricno_kriptiranje_ui).grid(column=0, row=3, pady=5, sticky='W')
        ttk.Button(frm, text="Simetrično dekriptiranje", command=self.simetricno_dekriptiranje_ui).grid(column=1, row=3, pady=5, sticky='W')

        ttk.Button(frm, text="Asimetrično kriptiranje", command=self.asimetricno_kriptiranje_ui).grid(column=0, row=4, pady=5, sticky='W')
        ttk.Button(frm, text="Asimetrično dekriptiranje", command=self.asimetricno_dekriptiranje_ui).grid(column=1, row=4, pady=5, sticky='W')

        ttk.Button(frm, text="Izračunaj sažetak (SHA-256)", command=self.izracunaj_sazetak_ui).grid(column=0, row=5, pady=5, sticky='W')
        ttk.Button(frm, text="Digitalno potpiši", command=self.potpisivanje_datoteke_ui).grid(column=0, row=6, pady=5, sticky='W')
        ttk.Button(frm, text="Provjeri digitalni potpis", command=self.provjeri_potpis_ui).grid(column=1, row=6, pady=5, sticky='W')

        ttk.Button(frm, text="Odustani", command=self.root.destroy).grid(column=2, row=6, pady=15, sticky='E')

        ttk.Label(frm, text="Log aktivnosti:").grid(column=0, row=7, columnspan=3, sticky='W', pady=(20, 5))
        self.log = scrolledtext.ScrolledText(frm, height=15, width=90, state='disabled')
        self.log.grid(column=0, row=8, columnspan=3)
        
        for i in range(3):
            frm.columnconfigure(i, weight=1)
        frm.rowconfigure(8, weight=1)
    
    def log_message(self, message):
        self.log.configure(state='normal')
        self.log.insert('end', message + '\n')  
        self.log.see('end')
        self.log.configure(state='disabled')
        self.root.update()

    def browse_file(self):
        path = filedialog.askopenfilename(title="Odaberite ulaznu datoteku")
        if path:
            self.input_path = path
            self.lbl_input.config(text=os.path.basename(path))
            self.log_message(f"Odabrana datoteka: {path}")
   

    def generiranje_i_spremanje_kljuceva(self):
        try:
            #generiranje simetricnog kljuca (Fernet)
            simetricni_kljuc = Fernet.generate_key()
            with open("tajni_kljuc.txt", "wb") as f:  #spremanje simetricnog kljuca
                f.write(simetricni_kljuc)
            
            #generiranje asimetricnih kljuceva (RSA)
            privatni_kljuc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            javni_kljuc = privatni_kljuc.public_key()

            # spremanje privatnog kljuca
            with open("privatni_kljuc.txt", "wb") as f:
                f.write(privatni_kljuc.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                    ))
    
            #spremanje javnog kljuca
            with open("javni_kljuc.txt", "wb") as f:
                f.write(javni_kljuc.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            self.log_message("Ključevi su generirani i spremljeni!")
        except Exception as e:
            self.log_message(f"Greška pri generiranju ključeva: {e}")
            
#----------------SIMETRIČNO KRIPTIRANJE I DEKRIPTIRANJE----------------------------------
    def simetricno_kriptiranje_ui(self):
        if not self.input_path:
            messagebox.showerror("Greška", "Prvo odaberite ulaznu datoteku!")
            return
        kriptirana_datoteka=self.input_path + ".enc"

        try:
            self.simetricno_kriptiranje(self.input_path, kriptirana_datoteka)
            self.log_message(f"Simetrično kriptiranje završeno, spremljeno u: {kriptirana_datoteka}")
        except Exception as e:
            self.log_message(f"Greška u simetričnom kriptiranju: {e}")

    def simetricno_kriptiranje(self, input_datoteka, kriptirana_datoteka):
        with open("tajni_kljuc.txt", "rb") as f:
            kljuc=f.read()

        fernet=Fernet(kljuc)

        with open(input_datoteka, "rb") as f:
            tekst=f.read()

        kriptiranje=fernet.encrypt(tekst)

        with open(kriptirana_datoteka, "wb") as f:
            f.write(kriptiranje)

    def simetricno_dekriptiranje_ui(self):
        kriptirana_datoteka=filedialog.askopenfilename(title="Odaberite kriptiranu datoteku (*.enc)", filetypes=[("Encrypted Files", "*.enc"), ("Sve datoteke", "*.*")])
        if not kriptirana_datoteka:
            return
        dekriptirana_datoteka=kriptirana_datoteka + ".dec"
        try:
            self.simetricno_dekriptiranje(kriptirana_datoteka, dekriptirana_datoteka)
            self.log_message(f"Simetrično dekriptiranje završeno, spremljeno u: {dekriptirana_datoteka}")
        except Exception as e:
            self.log_message(f"Greška u simetričnom dekriptiranju: {e}")

    def simetricno_dekriptiranje(self, kriptirana_datoteka, dekriptirana_datoteka):
        with open("tajni_kljuc.txt", "rb") as f:
            kljuc=f.read()
        
        fernet=Fernet(kljuc)

        with open(kriptirana_datoteka, "rb") as f:
            kriptirani_tekst=f.read()

        dekriptiranje=fernet.decrypt(kriptirani_tekst)

        with open(dekriptirana_datoteka, "wb") as f:
            f.write(dekriptiranje)
#----------------ASIMETRIČNO KRIPTIRANJE I DEKRIPTIRANJE----------------------------------  
    def asimetricno_kriptiranje_ui(self):
        if not self.input_path:
            messagebox.showerror("Greška", "Prvo odaberite ulaznu datoteku!")
            return
        kriptirana_datoteka_asim= self.input_path + ".rsa_enc"
        try:
            self.asimetricno_kriptiranje(self.input_path, kriptirana_datoteka_asim)
            self.log_message(f"Asimetrično kriptiranje završeno: {kriptirana_datoteka_asim}")
        except Exception as e:
            self.log_message(f"Greška u asimetričnom kriptiranju: {e}")

    def asimetricno_kriptiranje(self, input_datoteka, kriptirana_datoteka_asim):
        with open("javni_kljuc.txt", "rb") as f:
            javni_kljuc=serialization.load_pem_public_key(f.read())

        with open(input_datoteka, "rb") as f:
            tekst=f.read()

        kriptirano= javni_kljuc.encrypt( tekst, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        with open(kriptirana_datoteka_asim, "wb") as f:
            f.write(kriptirano)

    def asimetricno_dekriptiranje_ui(self):
        kriptirana_datoteka_asim = filedialog.askopenfilename(
            title="Odaberite RSA kriptiranu datoteku (*.rsa_enc)",
            filetypes=[("RSA Encrypted", "*.rsa_enc"), ("Svi", "*.*")]
        )
        if not kriptirana_datoteka_asim:
            return
        dekriptirana_datoteka_asim = kriptirana_datoteka_asim + ".dec"
        try:
            self.asimetricno_dekriptiranje(kriptirana_datoteka_asim, dekriptirana_datoteka_asim)
            self.log_message(f"Asimetrično dekriptiranje završeno: {dekriptirana_datoteka_asim}")
        except Exception as e:
            self.log_message(f"Greška u asimetričnom dekriptiranju: {e}")

    def asimetricno_dekriptiranje(self, kriptirana_datoteka_asim, dekriptirana_datoteka_asim):
        with open("privatni_kljuc.txt", "rb") as f:
            privatni_kljuc = serialization.load_pem_private_key(f.read(), password=None)
        
        with open(kriptirana_datoteka_asim, "rb") as f:
            kriptirani_tekst = f.read()
        
        # RSA dekriptiranje
        dekriptirano = privatni_kljuc.decrypt(
            kriptirani_tekst,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        with open(dekriptirana_datoteka_asim, "wb") as f:
            f.write(dekriptirano)


#----------------IZRAČUNAVANJE SAŽETKA PORUKE (SHA-256)----------------------------------
    def izracunaj_sazetak_ui(self):
        if not self.input_path:
            messagebox.showerror("Greška", "Prvo odaberite ulaznu datoteku")
            return
        sazetak_datoteka=self.input_path + ".sha256"
        try:
            self.izracunaj_sazetak(self.input_path, sazetak_datoteka)
            self.log_message(f"Sha256 sažetak spremljen u: {sazetak_datoteka}")
        except Exception as e:
            self.log_message(f"Greska u izracunavanju sazetka: {e} ")

    def izracunaj_sazetak(self, input_datoteka, sazetak_datoteka):
        sazetak=hashes.Hash(hashes.SHA256())
        with open(input_datoteka, "rb") as f:
            while True:
                blok=f.read(4096) 
                if not blok:
                    break
                sazetak.update(blok)
        hash_vrijednost=sazetak.finalize()

        with open(sazetak_datoteka, "wb") as f:
            f.write(hash_vrijednost)
    
#----------------DIGITALNO POTPISIVANJE----------------------------------
    def potpisivanje_datoteke_ui(self):
        if not self.input_path:
            messagebox.showerror("Greška", "Prvo odaberite ulaznu datoteku")
            return
        potpis_datoteka=self.input_path + ".sig"
        try:
            self.potpisivanje_datoteke(self.input_path, potpis_datoteka)
            self.log_message(f"Digitalni potpis spremljen u: {potpis_datoteka}")
        except Exception as e:
            self.log_message(f"Greska u potpisivanju: {e}")  

    def potpisivanje_datoteke(self, input_datoteka, potpis_datoteka):
        with open("privatni_kljuc.txt", "rb") as key_file:
            privatni_kljuc=serialization.load_pem_private_key(key_file.read(), password=None)

        #racunanje sazetka datoteke
        with open(input_datoteka, "rb") as f:
            tekst=f.read()
        
        potpis=privatni_kljuc.sign(tekst, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        with open(potpis_datoteka, "wb") as f:
            f.write(potpis)

#----------------PROVJERA DIGITALNOG POTPISA----------------------------------
    def provjeri_potpis_ui(self):
        input_datoteka = filedialog.askopenfilename(title="Odaberite originalnu datoteku")
        if not input_datoteka:
            return
        potpis_datoteka = filedialog.askopenfilename(title="Odaberite datoteku potpisa (*.sig)", filetypes=[("Signature", "*.sig")])
        if not potpis_datoteka:
            return
        try:
            rezultat = self.provjeri_potpis(input_datoteka, potpis_datoteka)
            if rezultat:
                messagebox.showinfo("Uspjeh", "Digitalni potpis je ispravan!")
                self.log_message("Digitalni potpis je ispravan!")
            else:
                messagebox.showerror("Greška", "Digitalni potpis nije ispravan!")
                self.log_message("Digitalni potpis nije ispravan!")
        except Exception as e:
            self.log_message(f"Greska prilikom provjere potpisa: {e} ") 

    def provjeri_potpis(self, input_datoteka, potpis_datoteka):
        with open("javni_kljuc.txt", "rb") as key_file:
            javni_kljuc=serialization.load_pem_public_key(key_file.read())

        with open(input_datoteka, "rb") as f:
            tekst=f.read()

        with open(potpis_datoteka, "rb") as f:
            potpis=f.read()

        try:
            javni_kljuc.verify(
                potpis,
                tekst,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        
if __name__ == "__main__":
    root=Tk()
    app=DigitalniPotpisGUI(root)
    root.mainloop()
