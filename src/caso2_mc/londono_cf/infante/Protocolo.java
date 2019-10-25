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
import java.security.NoSuchAlgorithmException;
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


public class Protocolo {
	
	public static void procedimiento(BufferedReader consoleReader, PrintWriter clientWriter, BufferedReader clientReader) {
		
//		java.security.cert.X509Certificate certificado = generarCertificado(llaves);
//		byte[] certificadoEnBytes = certificado.getEncoded( );
//		String certificadoEnString = printBase64Binary(certificadoEnBytes);
//		socketParaComunicacion.println(certificadoEnString);
		try {
		String protocolLine;			
		
		clientWriter.println("HOLA");
		protocolLine = clientReader.readLine();
		if(protocolLine != null)
		{
			System.out.println(protocolLine);
		}
		if(protocolLine.equals("OK")) 
		{

			String symmetricAlgorithm;

			int secretKeySize = 128;

			int keyPairSize = 1024;
			
			//Se selecciona algoritmo simetrico

			Random rand = new Random();
			  int randomNum = rand.nextInt((2 - 1) + 1) + 1;
			switch (randomNum) {
//			case 1:
//				symmetricAlgorithm = Cliente.AES;
//				break;
//			case 2:
//				symmetricAlgorithm = Cliente.BLOWFISH;
//				break;
			default:
				symmetricAlgorithm = Cliente.AES;
				break;
			}

			String asymmetricAlgorithm = Cliente.RSA;


			//seleccion de algoritmo HMAC
//			System.out.println("Seleccione un algoritmo HMAC : ");
//			System.out.println("1. HMACSHA1");
//			System.out.println("2. HMACSHA256");
//			System.out.println("3. HMACSHA384");
//			System.out.println("4. HMACSHA512");
//			linea = bfConsola.readLine();

			
			//seleccion de algoritmo HMAC
			String authOption;
			randomNum = rand.nextInt((4 - 1) + 1) + 1;

			switch (randomNum) {
			case 1:
				authOption = Cliente.HMACSHA1;
				break;
			case 2:
				authOption = Cliente.HMACSHA256;

				break;
			case 3:
				authOption = Cliente.HMACSHA384;
				break;
			case 4:
				authOption = Cliente.HMACSHA512;
				break;
			default :
				authOption = Cliente.HMACSHA512;
			}

			String algorithms = "ALGORITMOS:"+symmetricAlgorithm+":"+asymmetricAlgorithm+":"+authOption;
			
			clientWriter.println(algorithms);
			protocolLine = clientReader.readLine();
					
			if(protocolLine != null)
			{
				System.out.println(protocolLine);
			}
				
			//ETAPA 2
			if(!protocolLine.equals(Cliente.ERROR))
			{
//				System.out.println(algorithms);
				//Se genera el par de llaves: publica y privada
				KeyPairGenerator kp = KeyPairGenerator.getInstance(Cliente.RSA);
				kp.initialize(keyPairSize,new SecureRandom());
				KeyPair keys = kp.generateKeyPair();
				
				//Creacion del certificado
//				java.security.cert.X509Certificate certificado = generarCertificado(keys);
//				byte[] certificadoEnBytes = certificado.getEncoded( );
//				String certificadoEnString = printBase64Binary(certificadoEnBytes);
//				clientWriter.println(certificadoEnString);
				
				String serverCertificate = "";
				protocolLine = clientReader.readLine();
				if(protocolLine != null)
				{
					serverCertificate = protocolLine;
				}

				//Obtener llave publica servidor
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				byte[] certificadoServerEnBytes = parserBase64Binary(serverCertificate);
				InputStream in = new ByteArrayInputStream(certificadoServerEnBytes);
				X509Certificate certificadoServer = (X509Certificate) cf.generateCertificate(in);	
				
				//Se obtiene llave publica del servidor
				PublicKey llavePubServer = certificadoServer.getPublicKey();

				//obtencion de llave secreta(simetrica)
				KeyGenerator keygen = KeyGenerator.getInstance(symmetricAlgorithm);
				keygen.init(secretKeySize);
				SecretKey symmetricKey = keygen.generateKey();

				//cifrado respecto a la publica del servidor
				Cipher cifrador = Cipher.getInstance(asymmetricAlgorithm);
				byte[] llaveSecretaEnBytes = symmetricKey.getEncoded();
				cifrador.init(Cipher.ENCRYPT_MODE, llavePubServer);
				byte[] byteCifradoLlaveSimetrica = cifrador.doFinal(llaveSecretaEnBytes);

				//termina cifrado-------------------


				//envio de llave simetrica cifrada con publica del servidor
				clientWriter.println(printBase64Binary(byteCifradoLlaveSimetrica));
				String reto = Cliente.getClave();
				clientWriter.println(reto);

				//Mensaje que envia el servidor cifrado con llave simetrica
				protocolLine = clientReader.readLine();
				
				//Se desencripta el reto que envia de vuelta el servidor para ver si es la misma llave simetrica que generamos
				cifrador = Cipher.getInstance(symmetricAlgorithm);
				cifrador.init(Cipher.DECRYPT_MODE, symmetricKey);
				byte[] descifrado = parserBase64Binary(protocolLine);
				byte[] retoEnByte  = cifrador.doFinal(descifrado);
				String retoServidor = printBase64Binary(retoEnByte);
				
				//verificamos igualdad entre el reto generado por cliente y el reto que envia el servidor
				
				boolean continuar = false;	
				if(retoServidor.equals(reto))
				{
					System.out.println("Se realizo adecuadamente el intercambio de llave simetrica");
					clientWriter.println("OK");
					continuar = true;
				}
				else
				{
					System.out.println("No se intercambio correctamente la llave simetrica, lo sentimos.");
					clientWriter.println("ERROR");
				}

				//Llave secreta(version del server)
//				SecretKey key2 = new SecretKeySpec(retoEnByte, 0, retoEnByte.length, symmetricAlgorithm);
				

				if(continuar) 
				{
					//generamos datos
					String datos = Cliente.getCedula();
					byte[] datosEnBytes = parserBase64Binary(datos);
					String clave = Cliente.getClave();
					byte[] claveEnBytes = parserBase64Binary(clave);
					
					cifrador = Cipher.getInstance(symmetricAlgorithm);
					cifrador.init(Cipher.ENCRYPT_MODE, symmetricKey);
					byteCifradoLlaveSimetrica = cifrador.doFinal(datosEnBytes);
					clientWriter.println(printBase64Binary(byteCifradoLlaveSimetrica));
					
					cifrador = Cipher.getInstance(symmetricAlgorithm);
					cifrador.init(Cipher.ENCRYPT_MODE, symmetricKey);
					byteCifradoLlaveSimetrica = cifrador.doFinal(claveEnBytes);
					clientWriter.println(printBase64Binary(byteCifradoLlaveSimetrica));


					//--------------------fin de envio de cifrado simetrico de los datos
					
					//Valor de monto ahorro que responde el servidor
					protocolLine = clientReader.readLine();
					cifrador = Cipher.getInstance(symmetricAlgorithm);
					cifrador.init(Cipher.DECRYPT_MODE, symmetricKey);
					descifrado = parserBase64Binary(protocolLine);
					byte[] montoEnByte  = cifrador.doFinal(descifrado);
					String montoCliente = printBase64Binary(montoEnByte);
					System.out.println("El monto es de: " + montoCliente);
											
					//Se descifra con la llave publica del servidor
					protocolLine = clientReader.readLine();
					cifrador = Cipher.getInstance(asymmetricAlgorithm);
					cifrador.init(Cipher.DECRYPT_MODE, llavePubServer);
					descifrado = parserBase64Binary(protocolLine);
					byte[] hMacCifradoEnBytes  = cifrador.doFinal(descifrado);
					String hMac = printBase64Binary(hMacCifradoEnBytes);
					
					//HMAC de los datos
					Mac mac = Mac.getInstance(authOption);
				    mac.init(symmetricKey);
				    
				    byte[] bytesHMacDecrypt = mac.doFinal(montoEnByte);
					String hashCifradoenString = printBase64Binary(bytesHMacDecrypt);

					if(hMac.equals(hashCifradoenString))
					{
						System.out.println("Se encontro que estaba acorde el valor con su hmac(valor)");
						clientWriter.println(Cliente.OK);
					}
					else
					{
						System.out.println("No es igual valor con hmac(valor)");
						clientWriter.println(Cliente.ERROR);
					}
				}
				else
				{
					System.err.println(Cliente.ERROR);
				}
			}
			else
			{
				System.out.println("Error al enviar los algoritmos al servidor");
			}
		}
		else
		{
			System.out.println("El servidor no respondio.");
		}
		}
		catch (Exception e)
		{
			e.getMessage();
		}
	}
	
	public static String printBase64Binary(byte[] certificadoEnBytes) 
	{
		return DatatypeConverter.printBase64Binary(certificadoEnBytes);
	}
	
	public static byte[] parserBase64Binary(String certificadoEnBytes) 
	{
		return DatatypeConverter.parseBase64Binary(certificadoEnBytes);
	}

	public static java.security.cert.X509Certificate generarCertificado(KeyPair kp) 
	{
		try
		{
			
			Provider pro = new BouncyCastleProvider();
			Security.addProvider(pro);
			//fecha inicial de expedicion
			long fechaActual = System.currentTimeMillis();
			BigInteger sn = new BigInteger(Long.toString(fechaActual));
			Date fechaDefinitiva = new Date(fechaActual);

			X500Name name = new X500Name("CN=localhost");
			
			Date fechaFinal = new Date(System.currentTimeMillis());
			//Firma
			ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
			//Lo genero con mi publica para que el server lo pueda leer
			JcaX509v3CertificateBuilder constructorCertificador = new JcaX509v3CertificateBuilder(name, sn, fechaDefinitiva, fechaFinal, name, kp.getPublic());
			
			constructorCertificador.addExtension(new ASN1ObjectIdentifier("10.23.19"), true, new BasicConstraints(true));
			
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
