package caso2_mc.londono_cf.infante;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;





public class Protocolo {
	public static java.security.cert.X509Certificate generarCertificado(KeyPair kp) 
	{
		try
		{
			//para generar certificado
			
			//proveedor de certificados
			Provider pro = new BouncyCastleProvider();
			Security.addProvider(pro);
			//fecha inicial de expedicion
			long fechaActual = System.currentTimeMillis();
			BigInteger sn = new BigInteger(Long.toString(fechaActual));
			Date fechaDefinitiva = new Date(fechaActual);

			X500Name name = new X500Name("CN=localhost");
			
			//fecha final
			Date fechaFinal = new Date(System.currentTimeMillis());
			//Firma
			ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
			//Lo genero con mi publica para que el server lo pueda leer
			JcaX509v3CertificateBuilder constructorCertificador = new JcaX509v3CertificateBuilder(name, sn, fechaDefinitiva, fechaFinal, name, kp.getPublic());
			
			constructorCertificador.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, new BasicConstraints(true));
			
			//certificado obtenido
			X509Certificate certificado = new JcaX509CertificateConverter().setProvider(pro).getCertificate(constructorCertificador.build(signer));


			return certificado;

		}
		catch(OperatorCreationException  | CertificateException ce)
		{
			ce.printStackTrace();
			return null;
		} catch (CertIOException e) 
		{
			e.printStackTrace();
		}
		return null;
	}
}
