package snippet;

public class Snippet {
	public static void main(String[] args) {
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
		import javax.xml.bind.DatatypeConverter;
		
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
	}
}

