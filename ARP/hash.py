import hashlib

def hash_block(data):
    """ Hashes the data using SHA-256 and returns the hash as a binary string. """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def compute_merkle_root(file_path):
    """ Computes the Merkle root hash (h0) for the file by dividing it into 1KB blocks and chaining their hashes. """
    blocks = []
    
    # Read the file in 1KB blocks
    with open(file_path, 'rb') as file:
        while True:
            block = file.read(1024)
            if not block:
                break
            blocks.append(block)
    
    # Calculate hashes from the last block to the first
    for i in range(len(blocks) - 1, 0, -1):
        hash_next = hash_block(blocks[i])  # Hash of the current block
        blocks[i-1] += hash_next  # Append hash to the previous block

    # The hash of the first block with the appended hash of the second block is h0
    h0 = hash_block(blocks[0]).hex()  # Return hex representation of the hash
    return h0

# This function allows for testing of the computed Merkle root hash against known hash value.
def test_merkle_root_computation(file_path, expected_h0):
    computed_h0 = compute_merkle_root(file_path)
    return computed_h0, computed_h0 == expected_h0

# Example usage:
# test_merkle_root_computation('path_to_video.mp4', 'known_h0_hex_value')
# Đường dẫn đến file video sau khi đã tải xuống
video_path = r'C:\Users\Admin\Downloads\birthday.mp4'


# Giá trị h0 đã biết để kiểm tra
expected_h0 = '03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8'

# Chạy hàm kiểm tra
computed_h0, is_match = test_merkle_root_computation(video_path, expected_h0)

# Xuất kết quả
print("Computed h0:", computed_h0)
print("Does it match the known h0?", is_match)
