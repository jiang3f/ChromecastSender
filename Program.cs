using Imtiaz;
using Newtonsoft.Json.Linq;
using SslStreamTest;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Imtiaz
{
	using System;
	using System.IO;
	using System.Net;
	using System.Net.Sockets;
	using System.Text;
	using System.Threading;


	class MyWebServer
	{

		private TcpListener myListener;
		private int port = 5050; // Select any free port you wish

		//The constructor which make the TcpListener start listening on the
		//given port. It also calls a Thread on the method StartListen(). 
		public MyWebServer()
		{
			try
			{
				//start listing on the given port
				IPAddress localAddr = IPAddress.Parse("127.0.0.1");

				myListener = new TcpListener(localAddr, port);
				myListener.Start();
				Console.WriteLine("Web Server Running... Press ^C to Stop...");
				//start the thread which calls the method 'StartListen'
				Thread th = new Thread(new ThreadStart(StartListen));
				th.Start();

			}
			catch (Exception e)
			{
				Console.WriteLine("An Exception Occurred while Listening :" + e.ToString());
			}
		}


		/// <summary>
		/// Returns The Default File Name
		/// Input : WebServerRoot Folder
		/// Output: Default File Name
		/// </summary>
		/// <param name="sMyWebServerRoot"></param>
		/// <returns></returns>
		public string GetTheDefaultFileName(string sLocalDirectory)
		{
			StreamReader sr;
			String sLine = "";

			try
			{
				//Open the default.dat to find out the list
				// of default file
				sr = new StreamReader("data\\Default.Dat");

				while ((sLine = sr.ReadLine()) != null)
				{
					//Look for the default file in the web server root folder
					if (File.Exists(sLocalDirectory + sLine) == true)
						break;
				}
			}
			catch (Exception e)
			{
				Console.WriteLine("An Exception Occurred : " + e.ToString());
			}
			if (File.Exists(sLocalDirectory + sLine) == true)
				return sLine;
			else
				return "";
		}



		/// <summary>
		/// This function takes FileName as Input and returns the mime type..
		/// </summary>
		/// <param name="sRequestedFile">To indentify the Mime Type</param>
		/// <returns>Mime Type</returns>
		public string GetMimeType(string sRequestedFile)
		{


			StreamReader sr;
			String sLine = "";
			String sMimeType = "";
			String sFileExt = "";
			String sMimeExt = "";

			// Convert to lowercase
			sRequestedFile = sRequestedFile.ToLower();

			int iStartPos = sRequestedFile.IndexOf(".");

			sFileExt = sRequestedFile.Substring(iStartPos);

			try
			{
				//Open the Vdirs.dat to find out the list virtual directories
				sr = new StreamReader("data\\Mime.Dat");

				while ((sLine = sr.ReadLine()) != null)
				{

					sLine.Trim();

					if (sLine.Length > 0)
					{
						//find the separator
						iStartPos = sLine.IndexOf(";");

						// Convert to lower case
						sLine = sLine.ToLower();

						sMimeExt = sLine.Substring(0, iStartPos);
						sMimeType = sLine.Substring(iStartPos + 1);

						if (sMimeExt == sFileExt)
							break;
					}
				}
			}
			catch (Exception e)
			{
				Console.WriteLine("An Exception Occurred : " + e.ToString());
			}

			if (sMimeExt == sFileExt)
				return sMimeType;
			else
				return "";
		}



		/// <summary>
		/// Returns the Physical Path
		/// </summary>
		/// <param name="sMyWebServerRoot">Web Server Root Directory</param>
		/// <param name="sDirName">Virtual Directory </param>
		/// <returns>Physical local Path</returns>
		public string GetLocalPath(string sMyWebServerRoot, string sDirName)
		{

			StreamReader sr;
			String sLine = "";
			String sVirtualDir = "";
			String sRealDir = "";
			int iStartPos = 0;


			//Remove extra spaces
			sDirName.Trim();



			// Convert to lowercase
			sMyWebServerRoot = sMyWebServerRoot.ToLower();

			// Convert to lowercase
			sDirName = sDirName.ToLower();

			//Remove the slash
			//sDirName = sDirName.Substring(1, sDirName.Length - 2);


			try
			{
				//Open the Vdirs.dat to find out the list virtual directories
				sr = new StreamReader("data\\VDirs.Dat");

				while ((sLine = sr.ReadLine()) != null)
				{
					//Remove extra Spaces
					sLine.Trim();

					if (sLine.Length > 0)
					{
						//find the separator
						iStartPos = sLine.IndexOf(";");

						// Convert to lowercase
						sLine = sLine.ToLower();

						sVirtualDir = sLine.Substring(0, iStartPos);
						sRealDir = sLine.Substring(iStartPos + 1);

						if (sVirtualDir == sDirName)
						{
							break;
						}
					}
				}
			}
			catch (Exception e)
			{
				Console.WriteLine("An Exception Occurred : " + e.ToString());
			}


			Console.WriteLine("Virtual Dir : " + sVirtualDir);
			Console.WriteLine("Directory   : " + sDirName);
			Console.WriteLine("Physical Dir: " + sRealDir);
			if (sVirtualDir == sDirName)
				return sRealDir;
			else
				return "";
		}



		/// <summary>
		/// This function send the Header Information to the client (Browser)
		/// </summary>
		/// <param name="sHttpVersion">HTTP Version</param>
		/// <param name="sMIMEHeader">Mime Type</param>
		/// <param name="iTotBytes">Total Bytes to be sent in the body</param>
		/// <param name="mySocket">Socket reference</param>
		/// <returns></returns>
		public void SendHeader(string sHttpVersion, string sMIMEHeader, int iTotBytes, string sStatusCode, ref Socket mySocket)
		{

			String sBuffer = "";

			// if Mime type is not provided set default to text/html
			if (sMIMEHeader.Length == 0)
			{
				sMIMEHeader = "text/html";  // Default Mime Type is text/html
			}

			sBuffer = sBuffer + sHttpVersion + sStatusCode + "\r\n";
			sBuffer = sBuffer + "Server: cx1193719-b\r\n";
			sBuffer = sBuffer + "Content-Type: " + sMIMEHeader + "\r\n";
			sBuffer = sBuffer + "Accept-Ranges: bytes\r\n";
			sBuffer = sBuffer + "Content-Length: " + iTotBytes + "\r\n\r\n";

			Byte[] bSendData = Encoding.ASCII.GetBytes(sBuffer);

			SendToBrowser(bSendData, ref mySocket);

			Console.WriteLine("Total Bytes : " + iTotBytes.ToString());

		}



		/// <summary>
		/// Overloaded Function, takes string, convert to bytes and calls 
		/// overloaded sendToBrowserFunction.
		/// </summary>
		/// <param name="sData">The data to be sent to the browser(client)</param>
		/// <param name="mySocket">Socket reference</param>
		public void SendToBrowser(String sData, ref Socket mySocket)
		{
			SendToBrowser(Encoding.ASCII.GetBytes(sData), ref mySocket);
		}



		/// <summary>
		/// Sends data to the browser (client)
		/// </summary>
		/// <param name="bSendData">Byte Array</param>
		/// <param name="mySocket">Socket reference</param>
		public void SendToBrowser(Byte[] bSendData, ref Socket mySocket)
		{
			int numBytes = 0;

			try
			{
				if (mySocket.Connected)
				{
					if ((numBytes = mySocket.Send(bSendData, bSendData.Length, 0)) == -1)
						Console.WriteLine("Socket Error cannot Send Packet");
					else
					{
						Console.WriteLine("No. of bytes send {0}", numBytes);
					}
				}
				else
					Console.WriteLine("Connection Dropped....");
			}
			catch (Exception e)
			{
				Console.WriteLine("Error Occurred : {0} ", e);

			}
		}

		//This method Accepts new connection and
		//First it receives the welcome massage from the client,
		//Then it sends the Current date time to the Client.
		public void StartListen()
		{

			int iStartPos = 0;
			String sRequest;
			String sDirName;
			String sRequestedFile;
			String sErrorMessage;
			String sLocalDir;
			String sMyWebServerRoot = "d:\\vantage_store\\";
			String sPhysicalFilePath = "";
			String sFormattedMessage = "";
			String sResponse = "";



			while (true)
			{
				//Accept a new connection
				Socket mySocket = myListener.AcceptSocket();

				Console.WriteLine("Socket Type " + mySocket.SocketType);
				if (mySocket.Connected)
				{
					Console.WriteLine("\nClient Connected!!\n==================\nCLient IP {0}\n",
						mySocket.RemoteEndPoint);



					//make a byte array and receive data from the client 
					Byte[] bReceive = new Byte[1024];
					int i = mySocket.Receive(bReceive, bReceive.Length, 0);



					//Convert Byte to String
					string sBuffer = Encoding.ASCII.GetString(bReceive);



					//At present we will only deal with GET type
					if (sBuffer.Substring(0, 3) != "GET")
					{
						Console.WriteLine("Only Get Method is supported..");
						mySocket.Close();
						return;
					}


					// Look for HTTP request
					iStartPos = sBuffer.IndexOf("HTTP", 1);


					// Get the HTTP text and version e.g. it will return "HTTP/1.1"
					string sHttpVersion = sBuffer.Substring(iStartPos, 8);


					// Extract the Requested Type and Requested file/directory
					sRequest = sBuffer.Substring(0, iStartPos - 1);


					//Replace backslash with Forward Slash, if Any
					sRequest.Replace("\\", "/");


					//If file name is not supplied add forward slash to indicate 
					//that it is a directory and then we will look for the 
					//default file name..
					if ((sRequest.IndexOf(".") < 1) && (!sRequest.EndsWith("/")))
					{
						sRequest = sRequest + "/";
					}


					//Extract the requested file name
					iStartPos = sRequest.LastIndexOf("/") + 1;
					sRequestedFile = sRequest.Substring(iStartPos);


					//Extract The directory Name
					sDirName = sRequest.Substring(sRequest.IndexOf("/"), sRequest.LastIndexOf("/") - 3);



					/////////////////////////////////////////////////////////////////////
					// Identify the Physical Directory
					/////////////////////////////////////////////////////////////////////
					if (sDirName == "/")
						sLocalDir = sMyWebServerRoot;
					else
					{
						//Get the Virtual Directory
						sLocalDir = GetLocalPath(sMyWebServerRoot, sDirName);
					}


					Console.WriteLine("Directory Requested : " + sLocalDir);

					//If the physical directory does not exists then
					// dispaly the error message
					if (sLocalDir.Length == 0)
					{
						sErrorMessage = "<H2>Error!! Requested Directory does not exists</H2><Br>";
						//sErrorMessage = sErrorMessage + "Please check data\\Vdirs.Dat";

						//Format The Message
						SendHeader(sHttpVersion, "", sErrorMessage.Length, " 404 Not Found", ref mySocket);

						//Send to the browser
						SendToBrowser(sErrorMessage, ref mySocket);

						mySocket.Close();

						continue;
					}


					/////////////////////////////////////////////////////////////////////
					// Identify the File Name
					/////////////////////////////////////////////////////////////////////

					//If The file name is not supplied then look in the default file list
					if (sRequestedFile.Length == 0)
					{
						// Get the default filename
						sRequestedFile = GetTheDefaultFileName(sLocalDir);

						if (sRequestedFile == "")
						{
							sErrorMessage = "<H2>Error!! No Default File Name Specified</H2>";
							SendHeader(sHttpVersion, "", sErrorMessage.Length, " 404 Not Found", ref mySocket);
							SendToBrowser(sErrorMessage, ref mySocket);

							mySocket.Close();

							return;

						}
					}




					/////////////////////////////////////////////////////////////////////
					// Get TheMime Type
					/////////////////////////////////////////////////////////////////////

					String sMimeType = GetMimeType(sRequestedFile);



					//Build the physical path
					sPhysicalFilePath = sLocalDir + sRequestedFile;
					Console.WriteLine("File Requested : " + sPhysicalFilePath);


					if (File.Exists(sPhysicalFilePath) == false)
					{

						sErrorMessage = "<H2>404 Error! File Does Not Exists...</H2>";
						SendHeader(sHttpVersion, "", sErrorMessage.Length, " 404 Not Found", ref mySocket);
						SendToBrowser(sErrorMessage, ref mySocket);

						Console.WriteLine(sFormattedMessage);
					}

					else
					{
						int iTotBytes = 0;

						sResponse = "";

						FileStream fs = new FileStream(sPhysicalFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
						// Create a reader that can read bytes from the FileStream.


						BinaryReader reader = new BinaryReader(fs);
						byte[] bytes = new byte[fs.Length];
						int read;
						while ((read = reader.Read(bytes, 0, bytes.Length)) != 0)
						{
							// Read from the file and write the data to the network
							sResponse = sResponse + Encoding.ASCII.GetString(bytes, 0, read);

							iTotBytes = iTotBytes + read;

						}
						reader.Close();
						fs.Close();

						SendHeader(sHttpVersion, sMimeType, iTotBytes, " 200 OK", ref mySocket);
						SendToBrowser(bytes, ref mySocket);
						//mySocket.Send(bytes, bytes.Length,0);

					}
					mySocket.Close();
				}
			}
		}
	}
}

namespace SslStreamTest
{

	class Program
	{
		private static byte TYPE_ENUM = 0;
		private static byte TYPE_STRING = 2;
		private static byte TYPE_BYTES = TYPE_STRING;

		enum ProtocolVersion
		{
			CASTV2_1_0 = 0
		};

		private static ProtocolVersion protocolVersion = 0;

		private static string source_id = "sender-0";

		private static string destination_id = "receiver-0";

		// t-mobile
		//private static string chromecast_server = "10.0.19.83";
		// home
		private static string chromecast_server = "192.168.1.7";

		// ssl test server
		//private static string chromecast_server = "192.168.1.4";

		//private static string chromecast_server = "10.0.7.130";

		//private static int msgCount = 0;

		static string chrome_namespace = "urn:x-cast:com.google.cast.tp.connection";

		public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			/*if (sslPolicyErrors == SslPolicyErrors.None)
				return true;

			Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

			// Do not allow this client to communicate with unauthenticated servers.
			return false;
			*/
			return true;

		}

		public static void GetLenOf(string s, ref byte[] len, ref int bytes)
		{
			bytes = 0;
			Int32 length = s.Length;
			byte v;
			while (length > 0x7f)
			{
				Int32 length1 = length & 0xff;
				v = Convert.ToByte(length1);
				v &= 0x7f;
				v |= 0x80;
				len[bytes] = v;
				length = length >> 7;
				bytes++;
			}
			length = length & 0x7f;
			v = Convert.ToByte(length);
			len[bytes] = v;
			bytes++;
		}


		private static byte GetType(byte fieldId, byte t)
		{
			return (byte)((fieldId << 3) | (int)t);
		}

		public static byte[] CreateRequest(SslStream sslStream, string data, string dest = null)
		{
			byte[] msg = new byte[2048];

			// type:connect
			int payloadType = 0;
			byte[] len = new byte[4];
			int nLen = 0;
			GetLenOf(data, ref len, ref nLen);

			Console.WriteLine("Send: " + data);

			int offset = 4;
			msg[offset++] = GetType(1, TYPE_ENUM);
			msg[offset++] = (byte)protocolVersion;
			msg[offset++] = GetType(2, TYPE_STRING);
			msg[offset++] = (byte)source_id.Length;
			Encoding.ASCII.GetBytes(source_id, 0, source_id.Length, msg, offset);
			offset += source_id.Length;
			msg[offset++] = GetType(3, TYPE_STRING);
			if (dest != null)
			{
				msg[offset++] = (byte)dest.Length;
				Encoding.ASCII.GetBytes(dest, 0, dest.Length, msg, offset);
				offset += dest.Length;
			}
			else
			{
				msg[offset++] = (byte)destination_id.Length;
				Encoding.ASCII.GetBytes(destination_id, 0, destination_id.Length, msg, offset);
				offset += destination_id.Length;
			}
			msg[offset++] = GetType(4, TYPE_STRING);
			msg[offset++] = (byte)chrome_namespace.Length;
			Encoding.ASCII.GetBytes(chrome_namespace, 0, chrome_namespace.Length, msg, offset);
			offset += chrome_namespace.Length;
			msg[offset++] = GetType(5, TYPE_ENUM);
			msg[offset++] = (byte)payloadType;
			msg[offset++] = GetType(6, TYPE_BYTES);
			for (int i = 0; i < nLen; i++)
			{
				msg[offset++] = len[i];
			}
			Encoding.ASCII.GetBytes(data, 0, data.Length, msg, offset);
			offset += data.Length;

			byte[] intBytes = BitConverter.GetBytes(offset - 4);

			for (int i = 0; i < 4; i++)
			{
				msg[i] = intBytes[3 - i];
			}

			sslStream.Write(msg, 0, offset);
			sslStream.Flush();
			return msg;
		}

		static bool ReadMessage(SslStream sslStream, ref string response)
		{
			byte[] buffer = new byte[2048];
			Array.Clear(buffer, 0, 2048);

			int bytes = sslStream.Read(buffer, 0, buffer.Length);

			if (bytes != 0)
			{
				/*
				string readfn = "c:\\test\\read";
				readfn += msgCount.ToString();
				readfn += ".dat";

				using (BinaryWriter writer = new BinaryWriter(File.Open(readfn, FileMode.Create)))
				{
					writer.Write(buffer, 0, bytes);
				}
				*/

				// parsing protobuffer
				int offset = 4;
				offset += 3;

				// sender
				int len = (int)buffer[offset];
				offset++;
				offset += len;

				//receiver
				offset++;
				len = (int)buffer[offset];
				offset++;
				offset += len;

				//namespac
				offset++;
				len = (int)buffer[offset];
				offset++;
				offset += len;

				//data
				offset += 3;
				if (bytes < 200)
				{
					len = (int)buffer[offset];
					offset++;
				}
				else
				{
					//len = BitConverter.ToInt16(buffer, offset);

					offset += 2;
					len = bytes - offset;
				}
				len = bytes - offset;

				response = System.Text.Encoding.Default.GetString(buffer, offset, len);
				while (response.EndsWith("}") == false)
				{
					response = response.Remove(response.Length - 1);
				}

				return true;
			}
			return false;
		}


		public static string SendResponse(HttpListenerRequest request)
		{
			return string.Format("<HTML><BODY>My web page.<br>{0}</BODY></HTML>", DateTime.Now);
		}

		static void Main(string[] args)
		{
			try
			{
				MyWebServer MWS = new MyWebServer();

				TcpClient client = new TcpClient(chromecast_server, 8009);

				SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

				string data = null;
				string response = null;
				string sessionId = null;
				string transportId = null;

				//string[] response = new string[20];
				//int respCount = 0;

				//sslStream.AuthenticateAsClient("");
				sslStream.AuthenticateAsClient(chromecast_server, null, SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Default, false);
				sslStream.ReadTimeout = 100000;
				sslStream.WriteTimeout = 100000;

				// This is where you read and send data
				Console.WriteLine("connecting...");

				/* test code
				sessionId = "b6ec8bf8-e1a4-418d-88b6-8fe2b51ac057";
				transportId = "7cde1d99-aef8-44dc-a9f9-5d2050fc5594";

				data = "{\"type\":\"LOAD\",\"requestId\":46479002,\"sessionId\":\"" + sessionId + "\",\"media\":{\"contentId\":\"http://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4\",\"streamType\":\"buffered\",\"contentType\":\"video/mp4\"},\"autoplay\":true,\"currentTime\":0,\"customData\":{\"payload\":{\"title:\":\"Big Buck Bunny\",\"thumb\":\"images/BigBuckBunny.jpg\"}}}";
				chrome_namespace = "urn:x-cast:com.google.cast.media";
				CreateRequest(sslStream, data, transportId);
				// end of test code
				*/

				// connect
				data = "{\"type\":\"CONNECT\",\"origin\":{}}";
				chrome_namespace = "urn:x-cast:com.google.cast.tp.connection";
				CreateRequest(sslStream, data);

				// get status
				data = "{\"type\":\"GET_STATUS\",\"requestId\":46479000}";
				chrome_namespace = "urn:x-cast:com.google.cast.receiver";
				CreateRequest(sslStream, data);

				while (sessionId == null)
				{
					if (ReadMessage(sslStream, ref response) == false) return;

					if (response != null)
					{
						Console.WriteLine("response: " + response);
						var jObject = JObject.Parse(response);
						if (jObject["status"] != null)
						{
							if (jObject["status"]["applications"][0]["sessionId"] != null)
							{
								sessionId = jObject["status"]["applications"][0]["sessionId"].ToString();
								break;
							}
						}
					}
				}

				Console.WriteLine("session = " + sessionId);

				// PONG
				data = "{\"type\":\"PING\"}";
				chrome_namespace = "urn:x-cast:com.google.cast.tp.heartbeat";
				CreateRequest(sslStream, data);

				//launch
				//data = "{\"type\":\"LAUNCH\",\"requestId\":46479001,\"appId\":\"CC1AD845\"}";

				// CACD78FE is my receiver

				data = "{\"type\":\"LAUNCH\",\"requestId\":46479001,\"appId\":\"CACD78FE\"}";
				chrome_namespace = "urn:x-cast:com.google.cast.receiver";
				CreateRequest(sslStream, data);

				while (transportId == null)
				{
					if (ReadMessage(sslStream, ref response) == false) return;

					if (response != null)
					{
						Console.WriteLine("response: " + response);
						var jObject = JObject.Parse(response);
						if (jObject["status"] != null)
						{
							if (jObject["status"]["applications"] != null)
							{
								if (jObject["status"]["applications"][0]["transportId"] != null)
								{
									transportId = jObject["status"]["applications"][0]["transportId"].ToString();
									break;
								}
							}
						}
					}
				}
				Console.WriteLine("transportId= " + transportId);

				// PING AGAIN
				data = "{\"type\":\"PING\"}";
				chrome_namespace = "urn:x-cast:com.google.cast.tp.heartbeat";
				CreateRequest(sslStream, data);

				// connect to new destination
				data = "{\"type\":\"CONNECT\",\"origin\":{}}";
				chrome_namespace = "urn:x-cast:com.google.cast.tp.connection";
				CreateRequest(sslStream, data, transportId);

				// load
				data = "{\"type\":\"LOAD\",\"requestId\":46479002,\"sessionId\":\"" + sessionId + "\",\"media\":{\"contentId\":\"http://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4\",\"streamType\":\"buffered\",\"contentType\":\"video/mp4\"},\"autoplay\":true,\"currentTime\":0,\"customData\":{\"payload\":{\"title:\":\"Big Buck Bunny\",\"thumb\":\"images/BigBuckBunny.jpg\"}}}";
				//data = "{\"type\":\"LOAD\",\"requestId\":46479002,\"sessionId\":\"" + sessionId + "\",\"media\":{\"contentId\":\"http://localhost:5050/0\",\"streamType\":\"buffered\",\"contentType\":\"video/mp4\"},\"autoplay\":true,\"currentTime\":0,\"customData\":{\"payload\":{\"title:\":\"Big Buck Bunny\",\"thumb\":\"images/BigBuckBunny.jpg\"}}}";
				//data = "{\"type\":\"LOAD\",\"autoplay\":true,\"currentTime\":0,\"activeTrackIds\":[],\"media\":{\"contentId\":\"http://192.168.1.4/ED_1280.mp4\",\"contentType\":\"video/mp4\",\"streamType\":\"BUFFERED\",\"metadata\":{\"filePath\":\"d:\\vantage_store\\ED_1280.mp4\",\"title\":\"ED_1280.mp4\"}},\"requestId\"::46479002}";
				//data = "{\"type\":\"LOAD\",\"requestId\":46479002,\"sessionId\":\"" + sessionId + "\",\"media\":{\"contentId\":\"http://192.168.1.4/sourcempeg2_422_pro_ntsc.mp4\",\"streamType\":\"buffered\",\"contentType\":\"video/mp4\"},\"autoplay\":true,\"currentTime\":0,\"customData\":{\"payload\":{\"title:\":\"Big Buck Bunny\",\"thumb\":\"images/BigBuckBunny.jpg\"}}}";
				chrome_namespace = "urn:x-cast:com.google.cast.media";
				CreateRequest(sslStream, data, transportId);

				while (true)
				{
					if (ReadMessage(sslStream, ref response) == false) return;
					Console.WriteLine("response: " + response);

					// PING AGAIN
					data = "{\"type\":\"PING\"}";
					chrome_namespace = "urn:x-cast:com.google.cast.tp.heartbeat";
					CreateRequest(sslStream, data);

				}

				client.Close();
			}
			catch (System.Security.Authentication.AuthenticationException e)
			{
				Console.WriteLine("Exception: {0}", e.Message);
				if (e.InnerException != null)
				{
					Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
				}
				Console.WriteLine("Authentication failed - closing the connection.");
			}
			catch (Exception e)
			{
				Console.WriteLine("failed - closing the connection.");
			}

		}

		static void Main_save(string[] args)
		{
			TcpClient mail = new TcpClient();
			SslStream sslStream;
			int bytes = -1;

			//mail.Connect("pop.gmail.com", 995);
			mail.Connect("192.168.1.8", 8009);
			sslStream = new SslStream(mail.GetStream());

			sslStream.AuthenticateAsClient("192.168.1.8", null, SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Default, false);

			byte[] buffer = new byte[2048];
			// Read the stream to make sure we are connected
			bytes = sslStream.Read(buffer, 0, buffer.Length);
			Console.WriteLine(Encoding.ASCII.GetString(buffer, 0, bytes));

			//Send the users login details
			sslStream.Write(Encoding.ASCII.GetBytes("USER USER_EMAIL\r\n"));
			bytes = sslStream.Read(buffer, 0, buffer.Length);
			Console.WriteLine(Encoding.ASCII.GetString(buffer, 0, bytes));

			//Send the password                        
			sslStream.Write(Encoding.ASCII.GetBytes("PASS USER_PASSWORD\r\n"));
			bytes = sslStream.Read(buffer, 0, buffer.Length);
			Console.WriteLine(Encoding.ASCII.GetString(buffer, 0, bytes));

			// Get the first email 
			sslStream.Write(Encoding.ASCII.GetBytes("RETR 1\r\n"));
			bytes = sslStream.Read(buffer, 0, buffer.Length);
			Console.WriteLine(Encoding.ASCII.GetString(buffer, 0, bytes));
		}
	}
}
