int main() {
    int x = 5 * 5;

    *((int*)0) = 67;

    return x;
}