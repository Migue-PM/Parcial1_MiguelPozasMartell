import Crypto.Util.number
import hashlib
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

bits = 1024
archivo_contrato = "NDA.pdf"
e = 65537

# Mensaje
msg = "firmada por Alice"

# Primos de Alice
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

# Primera parte de la llave pública de Alice
nA = pA * qA
phiA = (pA - 1) * (qA - 1)

# Calcular llave privada Alice
dA = Crypto.Util.number.inverse(e, phiA)

# Hash del contrato
hash_contrato = hashlib.sha256(open(archivo_contrato, "rb").read()).hexdigest()
m = int(hash_contrato, 16)

# Firma de Alice
signature = pow(m, dA, nA)

# Agregar firma al PDF
with open(archivo_contrato, "rb") as f:
    reader = PdfReader(f)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    with open("NDA_firma.pdf", "wb") as output_pdf:
        c = canvas.Canvas(output_pdf)
        c.drawString(100, 100, msg + "\nFirma de Alice: " + str(signature))
        c.save()
        writer.write(output_pdf)

# AC verifica la firma de Alice
def verificar_firma_Alice(hash_contrato, signature, nA, e):
    m = int(hash_contrato, 16)
    decrypted_signature = pow(signature, e, nA)
    return m == decrypted_signature

if verificar_firma_Alice(hash_contrato, signature, nA, e):
    print("La firma de Alice es válida.")
else:
    print("La firma de Alice es inválida.")

# AC firma el documento
pAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
phiAC = (pAC - 1) * (qAC - 1)
dAC = Crypto.Util.number.inverse(e, phiAC)

hash_contrato_AC = hashlib.sha256(open("NDA_firma.pdf", "rb").read()).hexdigest()
m_AC = int(hash_contrato_AC, 16)
signature_AC = pow(m_AC, dAC, nAC)

# Agregar firma de AC al PDF
with open("NDA_firma.pdf", "rb") as f:
    reader = PdfReader(f)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    with open("NDA_firma_AC.pdf", "wb") as output_pdf:
        c = canvas.Canvas(output_pdf)
        c.drawString(100, 100, "Firma de AC: " + str(signature_AC))
        c.save()
        writer.write(output_pdf)

# Bob verifica la firma de AC
def verificar_firma_AC(hash_contrato_AC, signature_AC, nAC, e):
    m_AC = int(hash_contrato_AC, 16)
    decrypted_signature_AC = pow(signature_AC, e, nAC)
    return m_AC == decrypted_signature_AC

if verificar_firma_AC(hash_contrato_AC, signature_AC, nAC, e):
    print("La firma de AC es válida para Bob.")
else:
    print("La firma de AC es inválida para Bob.")

