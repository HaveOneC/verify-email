
#include <string>
#include <fstream>
#include <iostream>
#include "winsock2.h"
#pragma comment(lib,"ws2_32.lib")
using namespace std;
#define WSWENS MAKEWORD(2,0)
#define MAXLINE 10240


class Base64 {
public:
	string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";


	static inline bool is_base64(unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}

	string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
		string ret;
		int i = 0;
		int j = 0;
		unsigned char char_array_3[3];
		unsigned char char_array_4[4];

		while (in_len--) {
			char_array_3[i++] = *(bytes_to_encode++);
			if (i == 3) {
				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (i = 0; (i <4); i++)
					ret += base64_chars[char_array_4[i]];
				i = 0;
			}
		}

		if (i)
		{
			for (j = i; j < 3; j++)
				char_array_3[j] = '\0';

			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (j = 0; (j < i + 1); j++)
				ret += base64_chars[char_array_4[j]];
			while ((i++ < 3))
				ret += '=';
		}
		return ret;
	}

	string base64_decode(std::string const& encoded_string) {
		int in_len = encoded_string.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		unsigned char char_array_4[4], char_array_3[3];
		std::string ret;

		while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
			char_array_4[i++] = encoded_string[in_]; in_++;
			if (i == 4) {
				for (i = 0; i <4; i++)
					char_array_4[i] = base64_chars.find(char_array_4[i]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (i = 0; (i < 3); i++)
					ret += char_array_3[i];
				i = 0;
			}
		}

		if (i) {
			for (j = i; j <4; j++)
				char_array_4[j] = 0;

			for (j = 0; j <4; j++)
				char_array_4[j] = base64_chars.find(char_array_4[j]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
		}
		return ret;
	}
};


class CheckMail
{
public:
	CheckMail();
	~CheckMail();

	void response(SOCKET sock, char buff[]);
	void response(SOCKET sock, char buff[], int falg);
	void initialization();
	void connectSMTP();
	void sendHelo();
	void sendLogin();
	void sendMailFrom();
	void sendRcptTo();
	void quit();
	void readFile();
	void result();
	void setUserName(string username) { userName = username; }
	void setpassword(string pass) { password = pass; }
	void setToMail(string tomail) { toMail = tomail; }
	void setFromMail(string frommail) { fromMail = frommail; }
	void setSmtpIP() {
		int pos = fromMail.find("@");
		smtpIP = fromMail.substr(pos + 1, fromMail.length() - pos);
		smtpIP = "smtp." + smtpIP;
	}
private:
	SOCKET s;
	sockaddr_in sin;
	WSADATA wsadata;
	string userName;
	string password;
	string toMail;
	string fromMail;
	string smtpIP;

};

CheckMail::CheckMail()
{
}

CheckMail::~CheckMail()
{
}

void CheckMail::initialization() {
	//对Winsock服务初始化
	if (WSAStartup(WSWENS, &wsadata) != 0)
		cout << "startup failed" << endl;

	//创建套接字，指定端口号
	s = socket(PF_INET, SOCK_STREAM, 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(25);
	//获取服务器IP地址
	setSmtpIP();
	hostent* hptr = gethostbyname(smtpIP.c_str());
	memcpy(&sin.sin_addr.S_un.S_addr, hptr->h_addr_list[0], hptr->h_length);
	printf("IP of %s is : %d:%d:%d:%d", smtpIP.c_str(),
		sin.sin_addr.S_un.S_un_b.s_b1,
		sin.sin_addr.S_un.S_un_b.s_b2,
		sin.sin_addr.S_un.S_un_b.s_b3,
		sin.sin_addr.S_un.S_un_b.s_b4);
	cout << endl;
}

//将服务器回应的信息打印
void CheckMail::response(SOCKET sock, char buff[])
{
	int len = recv(sock, buff, MAXLINE, 0);
	buff[len] = 0;
	cout << "=" << buff << endl;
}

void CheckMail::response(SOCKET sock, char buff[], int flag)
{
	int len = recv(sock, buff, MAXLINE, 0);
	buff[len] = 0;
	string b(buff);
	cout << "=" << b << endl;
	string code = b.substr(0, 3);
	if (code == "250") {
		ofstream out("Mail_List_Successed.txt", ios::app);
		out << toMail << endl;
		out.close();
	}
	else {
		ofstream out("Mail_List_failed.txt", ios::app);
		out << toMail << endl;
		out.close();
	}
}

void CheckMail::connectSMTP() {
	//建立与服务器的连接
	if (connect(s, (sockaddr*)&sin, sizeof(sin)))
	{
		cout << "connect failed!" << endl;
		exit(0);
	}
	else
	{
		cout << "connect success!" << endl;
	}

	char bufferresv[10240];
	response(s, bufferresv);
}

void CheckMail::sendHelo() {
	// send "ehlo"
	char bufferHello[] = "ehlo lca\r\n";
	//cout << ">EHLO:" << endl;
	send(s, bufferHello, strlen(bufferHello), 0);
	char bufferresv[10240];
	//response(s, bufferresv);
}

void CheckMail::sendLogin() {
	// send "auth login"
	char bufferLogin[] = "auth login\r\n";
	cout << ">AUTH LOGIN:" << endl;
	send(s, bufferLogin, strlen(bufferLogin), 0);
	char bufferresv[10240];
	response(s, bufferresv);

	// send "username", "psw"
	Base64 base64;
	string bufferUserName = base64.base64_encode(reinterpret_cast<const unsigned char*>(userName.c_str()), userName.length());
	bufferUserName = bufferUserName + "\r\n";

	string bufferpsw = base64.base64_encode(reinterpret_cast<const unsigned char*>(password.c_str()), password.length());;
	bufferpsw = bufferpsw + "\r\n";

	send(s, bufferUserName.c_str(), bufferUserName.length(), 0);
	//response(s, bufferresv);
	send(s, bufferpsw.c_str(), bufferpsw.length(), 0);
	//response(s, bufferresv);
}

void CheckMail::sendMailFrom() {
	// mail from:<give_up_something@163.com>
	string bufferMailFrom = "mail from:<" + fromMail + ">\r\n";
	cout << ">MAIL FROM:<" << fromMail << ">" << endl;
	send(s, bufferMailFrom.c_str(), bufferMailFrom.length(), 0);
	char bufferresv[10240];
	response(s, bufferresv);
}

void CheckMail::sendRcptTo() {
	// rcpt to:<1019601243@qq.com>
	string bufferRcppTo = "rcpt to:<" + toMail + ">\r\n";
	cout << ">RCPT TO:<" << toMail << ">" << endl;
	send(s, bufferRcppTo.c_str(), bufferRcppTo.length(), 0);
	char bufferresv[10240];
	response(s, bufferresv, 1);
}

void CheckMail::quit() {
	//quit
	char bufferend[] = "quit\r\n";
	cout << ">QUIT:" << endl;
	send(s, bufferend, strlen(bufferend), 0);
	char bufferresv[10240];
	response(s, bufferresv);
}

int main(int argc, char **argv)
{
	CheckMail checkMail;


	/*checkMail.setUserName("give_up_something@163.com");
	checkMail.setpassword("review360427");*/
	if (argc != 4) {
		string exe(argv[0]);
		int pos = exe.rfind('\\');
		string a = exe.substr(pos+1,exe.length()-pos);
		printf("Useage:\r\n\t%s MailUserName MailPassword MailListFile\r\n",a);
		printf("For example:\r\n\t%s test@163.com p@ssw0rd mail.txt\r\n", a);
		getchar();
		return -1;
	}
	checkMail.setUserName(argv[1]);
	checkMail.setpassword(argv[2]);
	checkMail.setFromMail(argv[1]);

	checkMail.initialization();
	checkMail.connectSMTP();
	checkMail.sendHelo();
	checkMail.sendLogin();
	checkMail.sendMailFrom();

	cout << "==============To Mail==============" << endl;

	ifstream in(argv[3], ios::in);
	string toMail;
	while (getline(in, toMail)) {
		if (toMail == "")
			continue;
		checkMail.setToMail(toMail);
		checkMail.sendRcptTo();
	}

	checkMail.quit();
	in.close();             //关闭文件输入流 
	getchar();
	return 0;
}

