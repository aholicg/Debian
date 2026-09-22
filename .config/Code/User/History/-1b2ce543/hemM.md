# Bài 6. Lập trình ASM cơ bản
## Lý thuyết
#### 1. Các thanh ghi trong x86
*Nguồn tham khảo: [Intel® 64 and IA-32 Architectures](https://cdrdv2.intel.com/v1/dl/getContent/671436)*.
Gồm 16 thanh ghi cơ bản, chia làm 4 nhóm.
![alt text](image.png)

**Thanh ghi mục đích chung (General-purpose register)**
Các thanh ghi 32-bit EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP có các chức năng:
* Lưu trữ toán hạng cho phép toán số học/logic.
* Lưu trữ toán hạng cho phép toán địa chỉ.
* Lưu trữ địa chỉ.

Tuy nhiên, ESP theo quy ước chỉ dùng để lưu trữ con trỏ đến đỉnh stack.
Một số chức năng đặc biệt thường thấy ở các thanh ghi trên:
* EAX: lưu trữ toán hạng và kết quả phép toán.
* EBX: con trỏ đến dữ liệu trong phân đoạn của thanh ghi DS.
* ECX: bộ đếm cho phép toán xâu và vòng lặp.
* EDX: con trỏ I/O.
* ESI: con trỏ đến dữ liệu trong phân đoạn của DS, là con trỏ nguồn cho các phép xâu.
* EDI: con trỏ đến dữ liệu (hoặc đích đến) trong phân đoạn của ES, là con trỏ đích cho các phép toán xâu.
* ESP: Stack pointer.
* EBP: con trỏ đến dữ liệu trong stack.

**Thanh ghi phân đoạn (Segment register)**
Các thanh ghi CS, DS, SS, ES, FS, GS lưu trữ các bộ chọn đoạn 16-bit (segment selector). 1 bộ chọn đoạn là 1 con trỏ đặc biệt, có chức năng xác định 1 phân vùng trong bộ nhớ, được trỏ đến bởi thanh ghi phân đoạn.
* CS: lưu trữ bộ chọn đoạn cho phân đoạn mã (code segment) - nơi lưu trữ các lệnh đang thực thi. CS không thể được nạp tường minh bởi chương trình, mà được nạp ẩn bởi các lệnh/phép toán nội bộ của CPU. 
* SS: lưu trữ bộ chọn đoạn cho phân đoạn stack (stack segment). Mọi phép toán trên stack đều dùng SS để tìm phân đoạn stack. SS có thể được nạp tường minh, cho phép chương trình thiết lập nhiều stack để sử dụng.
* DS, ES, FS, GS: trỏ đến 4 phân vùng dữ liệu (data segment) cho các kiểu cấu trúc dữ liệu khác nhau như: 
  * CTDL của module hiện tại.
  * Dữ liệu xuất bởi module cấp cao hơn. 
  * CTDL được khởi tạo động.
  * Dữ liệu chia sẻ với chương trình khác.

**Thanh ghi EFLAGS (trạng thái và điều khiển chương trình)**
Là 1 thanh ghi 32-bit lưu trữ 1 nhóm bao gồm các cờ trạng thái, 1 cờ điều khiển, và 1 nhóm các cờ hệ thống.
Từ khởi tạo mặc định của CPU, trạng thái của của thanh ghi này là 0x00000002. Các bit 1, 3, 5, 15, và từ 22 đến 31 theo quy ước là các bit bảo tồn.
![alt text](image-1.png)

* Các cờ trạng thái: cho biết kết quả của phép toán số học.
  * CF (bit 0) - Carry flag: thiết lập nếu phép toán có nhớ trên most-significant bit của kết quả. 
  * PF (bit 2) - Parity flag: thiết lập nếu LSB của kết quả chứa số lượng chẵn bit 1.
  * AF (bit 4) - Auxiliary Carry flag: thiết lập nếu phép toán có nhớ trên bit 3 của kết quả.
  * ZF (bit 6) - Zero flag: thiết lập nếu kết quả = 0.
  * SF (bit 7) - Sign flag: thiết lập bằng bit most-significant của kết quả.
  * OF (bit 11) - Overflow flag: thiết lập nếu tràn số.

* Cờ DF (direction flag, bit 10): điều khiển các lệnh trên xâu. Thiết lập cờ này khiến lệnh tự động giảm - xử lý xâu từ địa chỉ cao xuống thấp, và ngược lại.

* Các cờ hệ thống và trường IOPL: điều khiển hệ điều hành. Các cờ này không nên được tùy chỉnh bởi chương trình.
  * TF (bit 8) - Trap flag: thiết lập debug chế độ từng bước.
  * IF (bit 9) - Interrupt enable flag: thiết lập phản hồi lại các yêu cầu ngắt từ phần cứng.
  * IOPL (bits 12, 13) - I/O privilege level field: cho biết mức ưu tiên truy cập I/O của chương trình hiện tại.
  * NT (bit 14) - Nested task flag: điều khiển chuỗi các tác vụ được gọi/ngắt. Thiết lập khi tác vụ hiện tại có liên kết tới tác vụ được thực thi trước đó.
  * RF (bit 16) - Resume flag: điều khiển phản hồi của CPU với các ngoại lệ debug.
  * VM (bit 17) - Virtual-8086 mode flag: 

#### 2. Calling convention...

## Thực hành