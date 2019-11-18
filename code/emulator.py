def byteval(n):
    return ((n % 0x100) + 0x100) % 0x100

class CPU:
    def __init__(self, image):
        assert len(image) < 0x100
        self.ram = bytearray(list(image) + [0] * (0xFF - len(image)))
        self.ax = 0
        self.bx = 0
        self.sp = 0
        self.pc = 0

    def fetch_single(self):
        ret = [self.ram[self.pc]]
        self.pc = byteval(self.pc + 1)

    def fetch(self):
        for _ in range(2):
            inst = [self.ram[self.pc]]
            self.pc = byteval(self.pc + 1)