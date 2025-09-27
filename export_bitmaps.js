import Java from "frida-java-bridge";
/*
 * frida_bitmap_exporter.js
 * 负责在 Android 进程中查找、导出 Bitmap，并清理目录。
 * 导出完成后，它会发送一个 'DONE' 消息给 Python 脚本。
 */
function exportBitmaps(save_path) {
    Java.perform(function () {
        send({type: 'info', message: 'Script loaded successfully.'});
    
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        const File = Java.use("java.io.File");
    
        try {
            const directory = File.$new(save_path);
            if (!directory.exists()) {
                send({type: 'info', message: `Preparing export directory: ${save_path}`});
                directory.mkdirs();
            } else {
                // 清空目录
                send({type: 'info', message: `Cleaning up directory: ${save_path}`});
                const files = directory.listFiles();
                if (files != null) {
                    for (let i = 0; i < files.length; i++) {
                        files[i].delete();
                    }
                }
            }
        } catch (e) {
            send({type: 'error', message: 'Failed to prepare export directory'});
            return; // 无法准备目录则直接退出
        }
    
        let bitmapCount = 0;
    
        Java.choose("android.graphics.Bitmap", {
            onMatch: function (bitmapInstance) {
                const recycled = bitmapInstance.isRecycled();
                if (recycled) {
                    send({type: 'info', message: `Skipping recycled bitmap: ${bitmapInstance}`});
                    return; // 跳过已回收的 Bitmap
                }
                // 跳过大小为 0 的 Bitmap
                if (bitmapInstance.getWidth() === 0 || bitmapInstance.getHeight() === 0) {
                    send({type: 'info', message: `Skipping empty bitmap: ${bitmapInstance}`});
                    return; // 跳过宽度或高度为 0 的 Bitmap
                }
                const width = bitmapInstance.getWidth();
                const height = bitmapInstance.getHeight();
                const filename = `bitmap_${new Date().getTime()}_${width}x${height}_${bitmapCount++}.png`;
                const filePath = save_path + filename;
    
                try {
                    const fileOutputStream = FileOutputStream.$new(filePath);
                    const success = bitmapInstance.compress(
                        Java.use("android.graphics.Bitmap$CompressFormat").PNG.value,
                        100,
                        fileOutputStream
                    );
                    if (success) {
                        send({type: 'info', message: `Successfully saved bitmap to: ${filePath}`});
                    } else {
                        send({type: 'error', message: 'Failed to compress and save bitmap'});
                    }
                    fileOutputStream.close();
                } catch (e) {
                    send({type: 'error', message: `Error saving bitmap: ${e}`});
                }
            },
            onComplete: function () {
                send({type: 'finish', message: 'All bitmaps exported'});
            }
        });
    });
}

rpc.exports = {
    exportbitmaps: exportBitmaps
};
