# Remote Template Injection

### 1. Lý thuyết

#### Kỹ thuật Remote Template Injection
**Định nghĩa**: Tạo hoặc sửa đổi các tham chiếu bên trong các tài liệu Microsoft Office OOXML (.docx, .xlsx, .pptx hoặc file .rtf). Vì các định dạng này cho phép tự động gọi đến các tài nguyên dùng chung qua URL khi tài liệu được nạp nên có thể lợi dụng để chèn các liên kết tới máy chủ C2.

*MITRE ATT&CK: [Template Injection - T1221](https://attack.mitre.org/techniques/T1221/)*

**Tính khả thi và độ phổ biến của RTI hiện nay**
* Trên bản Word mới nhất:

* Độ phổ biến hiện nay: được nhiều nhóm APT như FIN7, APT28, TA505, APT40,... sử dụng. *Tham khảo*: [cyfirma](https://www.cyfirma.com/research/living-off-the-land-the-mechanics-of-remote-template-injection-attack/) 


### 2 Phân tích tĩnh
Cấu trúc thư mục archive của file:
![alt text](image-5.png)
Trong file word/_rels/settings.xml.rels, tìm thấy đoạn trỏ đến `http://someofthelovercantbuyhappinessfromthe@shtu.be/5f0848`. (Đoạn `someofthelovercantbuyhappinessfromthe` có tác dụng obfuscate để tránh quét tĩnh phát hiện URL).
Cơ chế của đoạn này là khai thác thẻ Relationship với thuộc tính Type được thiết lập thành "attachedTemplate" kết hợp cùng TargetMode là "External" nhằm ép buộc Microsoft Word tự động tải về một tệp mẫu (template) từ URL từ xa ngay khi tài liệu được mở. Đó là nguồn gốc của tên gọi kỹ thuật Remote Template Injection. 
![alt text](image-13.png)
Tệp gốc kích hoạt Relationship này là word/settings.xml:
![alt text](image-14.png).
Thử nghiệm tạo PoC chỉ dùng 2 file word/settings.xml và word/_rels/settings.xml.rels với Id relationship thử nghiệm là `tId1`. Nguyên mẫu attachedTemplate theo [Microsoft](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oe376/7713efa6-b1ff-4cbd-9339-5bf9018433ac?utm_source=chatgpt.com).
![alt text](image-15.png)
![alt text](image-16.png)
Kết quả: PoC thành công.
![alt text](image-17.png)
![alt text](image-18.png)

### 3 Phân tích động
**Trên bản Office 2010**
Khi mở file, cửa sổ Microsoft Word hiện kết nối đến server và hành động tải từ URL: 
![alt text](image-2.png)
![alt text](image-1.png)
URL này được đánh dấu là đáng ngờ trên VirusTotal.
![alt text](image-9.png)
Bên trong word không hiện yêu cầu macro.
![alt text](image.png)

**Cây tiến trình**
Chỉ có đúng 1 tiến trình duy nhất: winword.exe
![alt text](image-3.png)

**Kết nối mạng**
IP máy ảo: 172.16.79.128 
Tìm thấy các gói tin tải https://shtu.be/5f0848 về từ địa chỉ IP 172.67.204.84 (địa chỉ sạch - của Cloudflare)
![alt text](image-6.png)

Nội dung stream download:
* Packet 1: GET /5f0848. Server trả về "301 Moved Permanently" nhưng `Location` trỏ về URL cũ.
![alt text](image-19.png)
* Gói 2: HEAD /5f0848. User-Agent: Microsoft Office Existence Discovery - là User-Agent mà Microsoft Office tự động gửi để kiểm tra một hyperlink có tồn tại hay không.
![alt text](image-20.png)

Trong ProcMon ghi nhận các hành động liên quan đến URL trên. Tuy nhiên, C2 server đã ngừng hoạt động nên mã độc chính không được tải về thành công.
![alt text](image-10.png)
2 file được tải về đều là Internet shortcut.
![alt text](image-11.png)
![alt text](image-12.png)

### 5. PoC
**Tạo thủ công như người dùng**
Không có cách tạo thủ công như người dùng. Kỹ thuật RTI được sử dụng nhiều do attachedTemplate là 1 cơ chế hoàn toàn hợp pháp của Microsoft, không phải lỗ hổng và không yêu cầu thông qua macro. 

**Script**
