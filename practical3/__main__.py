from sys import argv
from practical3.stage1 import extract_stage1_to_stage_2
from practical3.stage2 import extract_stage2_to_stage_3

# from .stage1 import extract_stage1_to_stage_2
# from .stage2 import extract_stage2_to_stage_3


def main(input_path, output_path):
    with open(input_path, 'rb') as f:
        input_file = f.read()
    stage2_bin = extract_stage1_to_stage_2(input_file)
    stage3_bin = extract_stage2_to_stage_3(stage2_bin)
    with open(output_path, 'wb') as f:
        f.write(stage3_bin)


if __name__ == '__main__':
    main(argv[1], argv[2])
