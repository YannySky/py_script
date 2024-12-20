import os
import re


def clean_filename(filename):
    # 替换文件名中的非法字符
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)  # 替换Windows系统中的非法字符
    return filename


def xor_decrypt(data, key):
    key_length = len(key)
    decrypted_data = bytearray()
    for i in range(0, len(data), key_length):
        data_segment = data[i:i + key_length]
        if len(data_segment) == key_length:
            for j in range(key_length):
                decrypted_data.append(data_segment[j] ^ key[j])
        else:
            for j in range(len(data_segment)):
                decrypted_data.append(data_segment[j] ^ key[j])
            for j in range(key_length - len(data_segment)):
                decrypted_data.append(key[j] ^ 0)  # 使用 0 作为填充
    return decrypted_data


def decrypt_file(input_filename, output_filename, key):
    print(f"Attempting to decrypt {input_filename} to {output_filename}")
    if not os.path.exists(os.path.dirname(output_filename)):
        print(f"Creating directory {os.path.dirname(output_filename)}")
        os.makedirs(os.path.dirname(output_filename))
    with open(input_filename, 'rb') as infile, open(output_filename, 'wb') as outfile:
        data = infile.read()
        if key is None:
            key = calc_encrypt_key([0x2f, 0x22, 0xbb, 0x8b])
        decrypted_data = xor_decrypt(data, key)
        outfile.write(decrypted_data)
        print(f'Decrypted {input_filename} to {output_filename}')


def decrypt_files_in_directory(src_dir, dest_dir, key):
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.smp'):
                src_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(src_file_path, src_dir)
                dest_file_path = os.path.join(dest_dir, relative_path).replace('.smp', '.mp3')
                # 清理文件名
                dest_file_name = clean_filename(os.path.basename(dest_file_path))
                dest_file_path = os.path.join(dest_dir, os.path.dirname(relative_path), dest_file_name)
                print(f"Processing file {src_file_path} to {dest_file_path}")
                decrypt_file(src_file_path, dest_file_path, key)

# mp3文件头部内容为 ID3+version，因此ID3V3,
mp3_file_head = [0x49, 0x44, 0x33, 0x3]


def calc_encrypt_key(data):
    # 读取data前4位，这4位是mp3_file_head与密钥按位异或的结果,反算得到密钥
    encrypt_key = [data[i] ^ mp3_file_head[i] for i in range(4)]
    # 输出以16进制形式展示的密钥数组
    print(f'密钥：', [hex(x) for x in encrypt_key])
    return encrypt_key


if __name__ == '__main__':
    # 假设的密钥
    # key = [0x66, 0x66, 0x88, 0x88]

    # 源目录和目标目录
    src_dir = "D:\\Download\\故事机音频（加密）"  # 替换为你的父文件夹路径

    dest_dir_suffix = '-解密'
    dest_dir = src_dir + dest_dir_suffix  # 新文件夹的路径

    # 开始解密
    decrypt_files_in_directory(src_dir, dest_dir, key=None)
