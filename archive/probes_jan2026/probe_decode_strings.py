#!/usr/bin/env python3
"""
Decode the Church-encoded strings properly.
"""

def decode_church_byte(data, pos=0):
    """
    Decode a Church-encoded byte from wire format.
    Format: 9 lambdas wrapping a bitwise expression.
    
    The pattern is: bit8(bit7(...bit1(0)...))
    Each bit_n applies Var(n) if set.
    
    Wire format starts with the bits, then 9 FE (lambdas).
    """
    # Find the 9 FE markers
    fe_count = 0
    end_pos = pos
    while end_pos < len(data) and fe_count < 9:
        if data[end_pos] == 0xFE:
            fe_count += 1
        end_pos += 1
        if fe_count == 9:
            break
    
    # Everything before the 9 FEs is the expression
    # Parse backwards from the bits
    bits = []
    i = pos
    while i < end_pos - 9:  # Before the FEs
        if data[i] < 0xFD:  # Var
            bits.append(data[i])
            i += 1
        elif data[i] == 0xFD:  # App
            i += 1
        else:
            break
    
    # Convert to byte value
    # Var(0) = base, Var(1) = bit 1 (value 1), ..., Var(8) = bit 8 (value 128)
    value = 0
    for b in bits:
        if 1 <= b <= 8:
            value |= (1 << (b - 1))
    
    return value, end_pos


def decode_string(data):
    """
    Decode a cons-list string from wire format.
    
    String = cons(byte1, cons(byte2, ... cons(byteN, nil)...))
    nil = λλ.0 = 00 FE FE
    cons(h, t) = λλ.(1 h t) = h t 01 FD FD FE FE
    
    Actually the encoding is more complex. Let me try to parse it character by character.
    """
    # The towel message starts with 01 (Left branch)
    # Then cons-encoded chars
    
    # Let me just try to extract the ASCII values from the response
    result = []
    
    # Each church-encoded byte looks like:
    # [bits and apps] FE FE FE FE FE FE FE FE FE (9 FEs)
    # Preceded by 01 (Left selector for the list element)
    
    i = 0
    while i < len(data):
        if data[i] == 0x01:  # Start of a character (Left branch of list cons)
            i += 1
            if i >= len(data):
                break
            
            # Now we have a church-encoded byte
            # Collect all bytes until we see 9 consecutive FEs
            start = i
            fe_count = 0
            while i < len(data):
                if data[i] == 0xFE:
                    fe_count += 1
                    i += 1
                    if fe_count == 9:
                        break
                elif data[i] == 0xFD:  # App marker
                    fe_count = 0
                    i += 1
                else:  # Var
                    fe_count = 0
                    i += 1
            
            # Parse the byte value from start to i-9
            byte_data = data[start:i-9] if i >= 9 else data[start:i]
            
            # The byte encoding is: applications of Var(1)..Var(8) to Var(0)
            # Each present bit adds that power of 2
            value = 0
            j = 0
            while j < len(byte_data):
                if byte_data[j] < 0xFD:  # It's a Var
                    var_idx = byte_data[j]
                    if 1 <= var_idx <= 8:
                        value |= (1 << (var_idx - 1))
                j += 1
            
            if value > 0:
                result.append(chr(value) if 32 <= value < 127 else f'\\x{value:02x}')
        elif data[i] == 0x00 and i + 2 < len(data) and data[i+1] == 0xFE and data[i+2] == 0xFE:
            # nil = end of list
            break
        else:
            i += 1
    
    return ''.join(result)


def decode_towel():
    """Decode the towel response."""
    # Raw towel response
    towel_hex = "0101070403020100fdfdfdfdfdfefefefefefefefefefefd01070604.."
    towel = bytes.fromhex("0101070403020100fdfdfdfdfdfefefefefefefefefefefd010706040"
                          "0fdfdfdfefefefefefefefefefefd0106040300fdfdfdfefefefefe"
                          "fefefefefefd010600fdfefefefefefefefefefefd010706030201"
                          "00fdfdfdfdfdfefefefefefefefefefefd010706040302010"
                          "0fdfdfdfdfdfdfefefefefefefefefefefd010600fdfefefefefe"
                          "fefefefefefd0107060201")
    
    # Actually let me decode byte by byte manually
    # Each char: 01 [bits] FD... FE FE FE FE FE FE FE FE FE
    
    test_data = bytes.fromhex("01010704030201")  # Should be 'O' = 0x4F = 79 = 64+8+4+2+1 = bits 7,4,3,2,1
    # bits 7(64), 4(8), 3(4), 2(2), 1(1) = 79
    
    # Let's decode: 01 01 07 04 03 02 01 00 FD FD FD FD FD FE FE FE FE FE FE FE FE FE
    # 01 = Left branch (cons)
    # Then: 01 07 04 03 02 01 00 FD FD FD FD FD = bit applications
    # Vars: 01, 07, 04, 03, 02, 01, 00
    # Wait, there are two 01s. The first is Left, second is Var(1)
    
    # Pattern: (((((((((Var(0)) @ Var(1)) @ Var(2)) @ Var(3)) @ Var(4)) @ Var(7)))))))
    # With 5 FDs for the 5 applications after Var(0)
    
    # For 'O' = 79 = 0b01001111 = bits 1,2,3,4,7 (1-indexed)
    # Expected: Var(7) @ (Var(4) @ (Var(3) @ (Var(2) @ (Var(1) @ Var(0)))))
    # Wire: 07 04 03 02 01 00 FD FD FD FD FD FE FE FE FE FE FE FE FE FE
    
    # Full char: 01 07 04 03 02 01 00 FD FD FD FD FD FE FE FE FE FE FE FE FE FE
    
    print("Decoding 'O' (79):")
    test = bytes([0x07, 0x04, 0x03, 0x02, 0x01, 0x00, 0xFD, 0xFD, 0xFD, 0xFD, 0xFD,
                  0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE])
    
    # The vars present are: 7, 4, 3, 2, 1 (excluding 0 which is the base)
    # Value = 2^6 + 2^3 + 2^2 + 2^1 + 2^0 = 64 + 8 + 4 + 2 + 1 = 79 ✓
    
    vars_present = [b for b in test if b < 0xFD and b > 0]
    value = sum(1 << (v - 1) for v in vars_present)
    print(f"  Vars: {vars_present}, Value: {value} = {chr(value)}")


def decode_full_string(data):
    """
    Properly decode a full string response.
    
    String encoding:
    - List = cons of bytes
    - Each cons: 01 [byte-encoding] FD [rest-of-list]
    - nil: 00 FE FE
    - byte-encoding: vars applied to base, then 9 FEs
    
    Actually, looking at the data more carefully:
    The 01 at the start is part of the cons structure, not just Left.
    
    cons(h, t) = λs. s h t = encoded as: h t 01 FD FD FE FE FE  
    Wait no, that's λλ.(1 h t)
    
    Let me trace through:
    Left = λλ.1 = 01 FE FE
    Right = λλ.0 = 00 FE FE
    
    cons(h, t) = λs. s h t where s is the selector
    As λ term: λ.((0 h) t) = h t 00 FD FD FE  -- no that's wrong too
    
    Actually: λ.((Var(0) H) T) where H and T are shifted by 1
    
    Looking at response: 01 01 07 04 03 02 01 00 FD FD FD FD FD FE FE...
    
    The first 01 might be the Left constructor from Either!
    
    Either Left x = λa.λb. a x = x 01 FD FE FE 
    Actually that's x 01 FD FE FE but the x comes first in postfix...
    
    Let me just manually trace the towel:
    """
    
    result = []
    i = 0
    
    while i < len(data) - 2:
        if data[i] == 0x00 and data[i+1] == 0xFE and data[i+2] == 0xFE:
            # nil - end of list
            break
        
        if data[i] == 0x01:
            # Start of cons cell
            i += 1
            
            # Collect vars until we hit FD
            vars_present = []
            while i < len(data) and data[i] < 0xFD:
                if data[i] > 0:  # Skip Var(0) as it's the base
                    vars_present.append(data[i])
                i += 1
            
            # Skip FDs and FEs
            while i < len(data) and data[i] >= 0xFD:
                i += 1
            
            # Calculate byte value
            if vars_present:
                value = sum(1 << (v - 1) for v in vars_present if 1 <= v <= 8)
                result.append(chr(value) if 32 <= value < 127 else f'[{value}]')
        else:
            i += 1
    
    return ''.join(result)


# Actually let me just test with a simpler approach
print("Testing string decoder:")
decode_towel()

print("\nDecoding 'P' (80):")
p_vars = [7, 5]
p_value = sum(1 << (v - 1) for v in p_vars)
print(f"  Vars: {p_vars}, Value: {p_value} = '{chr(p_value)}'")


if __name__ == "__main__":
    # Let's try the real data from the probe - error(6) = Permission denied
    real_err6 = bytes.fromhex(
        "0101070500fdfdfefefefefefefefefefefd"  # P
        "0107060301"
        "00fdfdfdfdfefefefefefefefefefefd"  # e
        "0107060502"
        "00fdfdfdfdfefefefefefefefefefefd"  # r
        "010706040301"
        "00fdfdfdfdfdfefefefefefefefefefefd"  # m
        "010706040100fdfdfdfdfefefefefefefefefefefd"  # i
        "01070605020100fdfdfdfdfdfefefefefefefefefefefd"  # s
        "01070605020100fdfdfdfdfdfefefefefefefefefefefd"  # s
        "010706040100fdfdfdfdfefefefefefefefefefefd"  # i
        "0107060403020100fdfdfdfdfdfdfefefefefefefefefefefd"  # o
        "01070604030200fdfdfdfdfdfefefefefefefefefefefd"  # n
        "010600fdfefefefefefefefefefefd"  # space
        "0107060300fdfdfdfefefefefefefefefefefd"  # d
        "0107060301"
        "00fdfdfdfdfefefefefefefefefefefd"  # e
        "01070604030200fdfdfdfdfdfefefefefefefefefefefd"  # n
        "010706040100fdfdfdfdfefefefefefefefefefefd"  # i
        "0107060301"
        "00fdfdfdfdfefefefefefefefefefefd"  # e
        "0107060300fdfdfdfefefefefefefefefefefd"  # d
        "00fefefd"  # nil start
    )
    
    print("\n" + "=" * 60)
    print("DECODING ACTUAL ERROR(6) RESPONSE")
    print("=" * 60)
    
    # Manual decode
    chars = []
    i = 0
    while i < len(real_err6):
        if real_err6[i] == 0x00 and i + 2 < len(real_err6) and real_err6[i+1] == 0xFE and real_err6[i+2] == 0xFE:
            break  # nil
        
        if real_err6[i] == 0x01:
            i += 1
            vars = []
            while i < len(real_err6) and real_err6[i] < 0xFD:
                if real_err6[i] > 0:
                    vars.append(real_err6[i])
                i += 1
            
            # Skip FDs
            while i < len(real_err6) and real_err6[i] == 0xFD:
                i += 1
            
            # Skip FEs (should be 9)
            fe_count = 0
            while i < len(real_err6) and real_err6[i] == 0xFE and fe_count < 9:
                i += 1
                fe_count += 1
            
            if vars:
                val = sum(1 << (v - 1) for v in vars if 1 <= v <= 8)
                chars.append(chr(val) if 32 <= val < 127 else f'[{val}]')
        else:
            i += 1
    
    print(f"  Decoded: {''.join(chars)}")
