import pytest
from cryptography.exceptions import InvalidTag
from coffre import chiffrer, dechiffrer, rechiffrer

def test_aller_retour():
    b = chiffrer("correct horse", "notes.txt", b"secret")
    assert dechiffrer("correct horse", "notes.txt", b) == b"secret"

def test_deux_chiffrements_differents():
    assert chiffrer("pw", "a", b"x") != chiffrer("pw", "a", b"x")

def test_mauvais_mot_de_passe():
    b = chiffrer("pw", "a", b"x")
    with pytest.raises(InvalidTag):
        dechiffrer("autre", "a", b)

def test_octet_modifie():
    b = bytearray(chiffrer("pw", "a", b"x" * 100))
    b[-20] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer("pw", "a", bytes(b))

def test_nom_echange():
    b = chiffrer("pw", "salaires.xlsx", b"x")
    with pytest.raises(InvalidTag):
        dechiffrer("pw", "menu.txt", b)

def test_rechiffrer():
    """Verifier que rechiffrer() change bien le mot de passe."""
    b_ancien = chiffrer("ancien", "doc.pdf", b"donnees sensibles")
    b_nouveau = rechiffrer("ancien", "nouveau", "doc.pdf", b_ancien)
    # Le nouveau mot de passe fonctionne
    assert dechiffrer("nouveau", "doc.pdf", b_nouveau) == b"donnees sensibles"
    # L'ancien mot de passe ne fonctionne plus sur le nouveau blob
    with pytest.raises(InvalidTag):
        dechiffrer("ancien", "doc.pdf", b_nouveau)

