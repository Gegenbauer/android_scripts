/*
 * frida_bitmap_exporter.js
 * 负责在 Android 进程中查找、导出 Bitmap，并清理目录。
 * 导出完成后，它会发送一个 'DONE' 消息给 Python 脚本。
 */

// 导出路径由 Python 脚本动态替换
const SAVE_PATH = "{{save_path}}";

Java.perform(function () {
    console.log("[*] Script loaded successfully.");

    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const File = Java.use("java.io.File");

    try {
        const directory = File.$new(SAVE_PATH);
        if (!directory.exists()) {
            console.log(`[+] Preparing export directory: ${SAVE_PATH}`);
            send({type: 'logd', message: `Preparing export directory: ${SAVE_PATH}`});
            directory.mkdirs();
        } else {
            // 清空目录
            console.log(`[+] Cleaning up directory: ${SAVE_PATH}`);
            send({type: 'logd', message: `Cleaning up directory: ${SAVE_PATH}`});
            const files = directory.listFiles();
            if (files != null) {
                for (let i = 0; i < files.length; i++) {
                    files[i].delete();
                }
            }
        }
    } catch (e) {
        console.error(`[-] Error while preparing export directory: ${e}`);
        send({type: 'error', message: 'Failed to prepare export directory'});
        return; // 无法准备目录则直接退出
    }

    let bitmapCount = 0;

    Java.choose("android.graphics.Bitmap", {
        onMatch: function (bitmapInstance) {
            const recycled = bitmapInstance.isRecycled();
            if (recycled) {
                console.log(`[-] Skipping recycled bitmap: ${bitmapInstance}`);
                send({type: 'logd', message: `Skipping recycled bitmap: ${bitmapInstance}`});
                return; // 跳过已回收的 Bitmap
            }
            // 跳过大小为 0 的 Bitmap
            if (bitmapInstance.getWidth() === 0 || bitmapInstance.getHeight() === 0) {
                console.log(`[-] Skipping empty bitmap: ${bitmapInstance}`);
                send({type: 'logd', message: `Skipping empty bitmap: ${bitmapInstance}`});
                return; // 跳过宽度或高度为 0 的 Bitmap
            }
            const width = bitmapInstance.getWidth();
            const height = bitmapInstance.getHeight();
            const filename = `bitmap_${new Date().getTime()}_${width}x${height}_${bitmapCount++}.png`;
            const filePath = SAVE_PATH + filename;

            try {
                const fileOutputStream = FileOutputStream.$new(filePath);
                const success = bitmapInstance.compress(
                    Java.use("android.graphics.Bitmap$CompressFormat").PNG.value,
                    100,
                    fileOutputStream
                );
                if (success) {
                    console.log(`[+] Successfully saved bitmap to: ${filePath}`);
                    send({type: 'logd', message: `Successfully saved bitmap to: ${filePath}`});
                } else {
                    console.log(`[-] Failed to compress and save bitmap.`);
                    send({type: 'loge', message: 'Failed to compress and save bitmap'});
                }
                fileOutputStream.close();
            } catch (e) {
                console.error(`[-] Error saving bitmap: ${e}`);
                send({type: 'loge', message: `Error saving bitmap: ${e}`});
            }
        },
        onComplete: function () {
            console.log("[*] Finished iterating through all Bitmap instances.");
            // 导出完成后，发送 'DONE' 消息给 Python 脚本
            send({type: 'finish', message: 'All bitmaps exported'});
        }
    });
});