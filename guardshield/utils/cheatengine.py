import win32file
import win32con
import win32api
import re

FILE_LIST_DIRECTORY = 0x0001
FILE_ACTION_ADDED = 0x00000001
FILE_ACTION_REMOVED = 0x00000002

ASYNC_TIMEOUT = 5000
BUF_SIZE = 65536


blacklist_strings = ('ADDRESSES.FIRST','ADDRESSES.TMP','MEMORY.FIRST','MEMORY.TMP','ADDRESSES.TMP.FILETEST','ADDRESSES.TMP.FI')
blacklist_patterns = (r"ADDRESSES-\d+\.TMP", r"MEMORY-\d+\.TMP")

def get_dir_handle(dir_name):
    flags_and_attributes = win32con.FILE_FLAG_BACKUP_SEMANTICS
    dir_handle = win32file.CreateFile(
        dir_name,
        FILE_LIST_DIRECTORY,
        (win32con.FILE_SHARE_READ |
         win32con.FILE_SHARE_WRITE |
         win32con.FILE_SHARE_DELETE),
        None,
        win32con.OPEN_EXISTING,
        flags_and_attributes,
        None
    )
    return dir_handle

def read_dir_changes(dir_handle, size_or_buf, overlapped):
    return win32file.ReadDirectoryChangesW(
        dir_handle,
        size_or_buf,
        True,
        (win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
         win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
         win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
         win32con.FILE_NOTIFY_CHANGE_SIZE |
         win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
         win32con.FILE_NOTIFY_CHANGE_SECURITY),
        overlapped,
        None
    )

def handle_results(results):
    for item in results:
        _action, _ = item
        for i in blacklist_strings:
            if i in _:
                return True
        for i in blacklist_patterns:
            matches = re.findall(i, _)
            if matches:
                return True
    return False

def monitor_dir_sync(dir_handle):
    idx = 0
    while True:
        idx += 1
        results = read_dir_changes(dir_handle, BUF_SIZE, None)
        res = handle_results(results)
        if res == True:
            return True

def monitor_dir(dir_name):
    dir_handle = get_dir_handle(dir_name)
    res = monitor_dir_sync(dir_handle)
    win32api.CloseHandle(dir_handle)
    return res


