import psutil


def kill_processes():
    try:
        # Lấy danh sách tất cả các tiến trình đang chạy
        all_processes = psutil.process_iter()

        # Duyệt qua từng tiến trình
        for process in all_processes:
            print(f"{process.name()}")
            try:
                # Kiểm tra nếu tên tiến trình chứa "Zalo"
                if "MongoDBCompass" in process.name():
                    # Tắt tiến trình
                    process.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    except Exception as e:
        print(f"Lỗi: {e}")


kill_processes()
