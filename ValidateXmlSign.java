import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.PublicKey;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import lombok.extern.slf4j.Slf4j;
@Slf4j
public class ValidateXmlSign {
	public static PublicKey publicKey;
	
	public static boolean isValidXmlSign(final String xmlStr) {
		log.trace("In isValidXmlSign");
		boolean isSignatureValid = false;
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xmlStr.getBytes()));
			NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (nl.getLength() == 0) {
				throw new Exception("Signature element not found");
			}
			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
			DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));
			XMLSignature signature = fac.unmarshalXMLSignature(valContext);
			isSignatureValid = signature.validate(valContext);
			log.trace("isSignatureValid={}", isSignatureValid);
		} catch (Exception e) {
			log.error("error while validating xml signature {}", e.getMessage());
		}
		return isSignatureValid;
	}
	
	private static class KeyValueKeySelector extends KeySelector {
		public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
				XMLCryptoContext context) throws KeySelectorException {

			return new SimpleKeySelectorResult(publicKey);
		}
	}

	private static class SimpleKeySelectorResult implements KeySelectorResult {
		private PublicKey pk;

		SimpleKeySelectorResult(PublicKey pk) {
			this.pk = pk;
		}

		public Key getKey() {
			return pk;
		}
	}
}
