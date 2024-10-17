import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Lazy(false)
@Slf4j
public class CertificateConfig {
	
	@Value("${pub.key.path}")
	private String pubFile;
	
	@Value("${pvt.key.path}")
	private String pvtFile;
	
	@Value("${pvt.key.type}")
	private String pvtType;
	
	@Value("${pvt.key.password}")
	private String pvtPass;
	
	@Value("${pvt.key.alais}")
	private String pvtAlias;
	
	@Value("${error.property.path}")
	private String errorpropertypath;
	
	@Bean(name = Constants.PPI_PVT_KEY)
	public PrivateKey upiPrivateKey() throws Exception {
		return getPrivateKey();
	}
	
	@Bean(name = Constants.PPI_NPCI_PUB_KEY)
	public PublicKey upiNpciPublicKey() throws Exception {
		return getCertificate();
	}
	
	
	private PrivateKey getPrivateKey() throws Exception {
		InputStream in = null;
		try {
			KeyStore keystore = KeyStore.getInstance(pvtType);
			in = new FileInputStream(new File(pvtFile));
			String password = AESEncryptionUtility.decrypt(pvtPass, AESEncryptionUtility.secretKeys);		
			keystore.load(in, password.toCharArray());
			PrivateKey key = (PrivateKey) keystore.getKey(pvtAlias, password.toCharArray());
			log.info("private key loaded {}", key);
			return key;
		} catch (Exception e) {
			log.error("Error while loading Private Key ", e);
		} finally {
			if (in != null)
				in.close();
		}
		return null;
	}
	
	private PublicKey getCertificate() throws Exception {
		CertificateFactory cf = CertificateFactory.getInstance(Constants.X509);
		InputStream in = new FileInputStream(new File(pubFile));
		InputStream caInput = new BufferedInputStream(in);
		Certificate ca;
		try {
			ca = cf.generateCertificate(caInput);
			log.info("public key loaded");
			return ca.getPublicKey();
		} finally {
			try {
				caInput.close();
			} catch (IOException e) {
				log.error("error IO Exception in Public key loding 1");
			}
			try {
				in.close();
			} catch (IOException e) {
				log.error("error IO Exception in Public key loding 2");
			}
		}
	}
	
	@Bean(name = Constants.UPI_ERROR_SOURCE)
	public MessageSource messageSource() {
		ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
		log.info("error property path {}", errorpropertypath);
		messageSource.setBasenames(errorpropertypath);
		// if true, the key of the message will be displayed if the key is not
		// found, instead of throwing a NoSuchMessageException
		messageSource.setUseCodeAsDefaultMessage(true);
		messageSource.setDefaultEncoding("UTF-8");
		// # -1 : never reload, 0 always reload
		messageSource.setCacheSeconds(0);
		log.info("{}",messageSource.getBasenameSet());
		return messageSource;
	}
}
