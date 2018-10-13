package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_STORE_FILE = "./data/korisnika.jks";
	private static final String KEY_STORE_FILE1 = "./data/korisnikb.jks";

	static {
		// staticka inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	public static void main(String[] args) {

		try {
			Gmail service = getGmailService();

			// Unos podataka
			System.out.println("Insert a reciever:");
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			String reciever = reader.readLine();

			System.out.println("Insert a subject:");
			String subject = reader.readLine();

			System.out.println("Insert body:");
			String body = reader.readLine();

			// kreiranje xml dokumenta
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("mail");

			rootElement.setTextContent(body);
			doc.appendChild(rootElement);

			// dokument pre enkripcije u string formatu
			String xml = xmlAsString(doc);
			System.out.println("Email pre enkripcije: " + xml);
			
			
			//ucitava privatni kljuc koji ce biti iskoriscen za potpisivanje dokumenta
			PrivateKey pk = readPrivateKey();
			
			//ucitava sertifikat
			Certificate cert = readCertificate();
			
			Certificate certSig = readCertificateSig() ;
			
			//potpisuje dokument
			System.out.println("Signing....");
			doc = signDocument(doc, pk, certSig);
			
			
			System.out.println("Signing of document done");
			//>>>>>>>>>>>>>>>>
			
			
			// generisanje tajnog (session) kljuca*****************************************
			// SIMETRICNI KLJUC
			SecretKey secretKey = generateSessionKey();
			
			
			// cipher za kriptovanje XML-a
			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
						
			// inicijalizacija za kriptovanje
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

			// cipher za kriptovanje tajnog kljuca javnim RSA kljucem
			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
						
			// inicijalizacija za kriptovanje tajnog kljuca javnim RSA kljucem
			keyCipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());
						
			// kreiranje EncryptedKey objekta koji sadrzi  enkriptovan tajni (session) kljuc
			EncryptedKey encryptedKey = keyCipher.encryptKey(doc, secretKey);
						
			// u EncryptedData element koji se kriptuje kao KeyInfo stavljamo
			// kriptovan tajni kljuc
			// ovaj element je korenski element XML enkripcije
			EncryptedData encryptedData = xmlCipher.getEncryptedData();
						
			// kreira se KeyInfo element
			KeyInfo keyInfo = new KeyInfo(doc);
						
			// postavljamo naziv 
			keyInfo.addKeyName("Kriptovani tajni kljuc");
						
			// postavljamo kriptovani kljuc
			keyInfo.add(encryptedKey);
						
			// postavljamo KeyInfo za element koji se kriptuje
			encryptedData.setKeyInfo(keyInfo);
			
			//TODO 6: kriptovati sadrzaj dokumenta
			xmlCipher.doFinal(doc, rootElement, true);

			// Slanje poruke
			String encryptedXml = xmlAsString(doc);
			System.out.println("Email posle enkripcije: " + encryptedXml);

			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, subject, encryptedXml);
			MailWritter.sendMessage(service, "me", mimeMessage);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	//prebacivanje u String format
	private static String xmlAsString(Document doc) throws TransformerException {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		String output = writer.getBuffer().toString().replaceAll("\n|\r", "");

		return output;
	}

	// TODO 1 - generisi tajni (session) kljuc
	private static SecretKey generateSessionKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
		return keyGenerator.generateKey();
	}

	// TODO 2 - iz sertifikata korisnika B izvuci njegov javni kljc
	private static PublicKey getPublicKey() throws ParseException {
		
		String alias = "123";
		String pass = "123";
		KeyStoreReader kr = new KeyStoreReader();
		kr.readKeyStore("./data/korisnikA.jks", "korisnikb", alias.toCharArray(), pass.toCharArray());
			
		return kr.readPublicKey();
	}
	
	private static PrivateKey readPrivateKey() {
		//Korisnik A potpisuje svojim privatnim
		try {
			//kreiramo instancu KeyStore
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			
			//ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(KEY_STORE_FILE));
			ks.load(in, "123".toCharArray());
			
			if(ks.isKeyEntry("korisnika")) {
				PrivateKey pk = (PrivateKey) ks.getKey("korisnika", "123".toCharArray());
				return pk;
			}
			else
				return null;
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
	private static Certificate readCertificate() {
		//Javni kljuc KORISNIK B sifruje tajni kljuc
		try {
			//kreiramo instancu KeyStore
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			
			//ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(KEY_STORE_FILE));
			ks.load(in, "123".toCharArray());
			
			if(ks.isKeyEntry("korisnika")) {
				Certificate cert = ks.getCertificate("korisnikb");
				return cert;
				
			}
			else
				return null;
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	// POTPISIVANJE DOKUMENTA
	private static Document signDocument(Document doc, PrivateKey privateKey, Certificate cert) {
	      
	      try {
				Element rootEl = doc.getDocumentElement();
				
				//kreira se signature objekat
				XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
				
				//kreiraju se transformacije nad dokumentom
				Transforms transforms = new Transforms(doc);
				    
				//iz potpisa uklanja Signature element
				//Ovo je potrebno za enveloped tip po specifikaciji
				transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
				
				//normalizacija
				transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
				    
				//potpisuje se citav dokument (URI "")
				sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
				    
				//U KeyInfo se postavalja Javni kljuc samostalno i citav sertifikat
				sig.addKeyInfo(cert.getPublicKey());
				sig.addKeyInfo((X509Certificate) cert);
				    
				//potpis je child root elementa
				rootEl.appendChild(sig.getElement());
				
				//potpisivanje
				sig.sign(privateKey);
				
				return doc;
				
			} catch (TransformationException e) {
				e.printStackTrace();
				return null;
			} catch (XMLSignatureException e) {
				e.printStackTrace();
				return null;
			} catch (DOMException e) {
				e.printStackTrace();
				return null;
			} catch (XMLSecurityException e) {
				e.printStackTrace();
				return null;
			}
		}
	
	private static Certificate readCertificateSig() {
		//Sertifikat KORISNIKA A
		try {
			//kreiramo instancu KeyStore
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			
			//ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(KEY_STORE_FILE));
			ks.load(in, "123".toCharArray());
			
			if(ks.isKeyEntry("korisnika")) {
				Certificate cert = ks.getCertificate("korisnika");
				return cert;
				
			}
			else
				return null;
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	
	
	
}
