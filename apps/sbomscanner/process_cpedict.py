import sys

def process_input(input_stream):
    for line in input_stream:
        if "cpe" not in line:
            sys.stdout.write(line.replace("\n", "|"))
        else:
            sys.stdout.write(line)

if __name__ == "__main__":
    process_input(sys.stdin)