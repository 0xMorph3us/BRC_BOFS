WCHAR* ConvertCharToWideString(const char* source) {
    if (!source) {
        return NULL;
    }

    int requiredSize = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, source, -1, NULL, 0);
    if (requiredSize <= 0) {
        return NULL;
    }

    WCHAR* destination = (WCHAR*)BadgerAlloc(requiredSize * sizeof(WCHAR));
    if (!destination) {
        return NULL;
    }

    if (KERNEL32$MultiByteToWideChar(CP_UTF8, 0, source, -1, destination, requiredSize) == 0) {
        BadgerFree((PVOID*)&destination);
        return NULL;
    }

    return destination;
}