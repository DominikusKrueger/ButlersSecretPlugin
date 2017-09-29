package de.kruegersolutions.butlerssecretplugin.cryption;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Dominikus on 27.06.2017.
 * A lot of this is adapted from
 * http://www.coderzheaven.com/2013/03/19/encrypt-decrypt-file-aes-algorithm-android/
 */

public class Utils {

    private final static String TAG = Utils.class.getSimpleName();
    private final static boolean DEBUG = true;

    private static final String ALGORITHM = "AES/CBC/ISO10126Padding";

    private static byte[] encodeFile(String key, byte[] fileData) throws Exception{
        return codeFile(Cipher.ENCRYPT_MODE, key, fileData);
    }

    private static byte[] decodeFile(String key, byte[] fileData) throws Exception{
        return codeFile(Cipher.DECRYPT_MODE, key, fileData);
    }



    /**
     *
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param key the key to code the file
     * @param fileData the file to code
     * @return the coded data
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private static byte[] codeFile(int mode, String key, byte[] fileData) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if(mode != Cipher.DECRYPT_MODE && mode != Cipher.ENCRYPT_MODE)
            throw new RuntimeException("Wrong usage of this methods signature! Use Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE!");

        byte[] changedData;
        byte[] keyBytes = key.getBytes("UTF-8");
        SecretKeySpec sKeySpec = new SecretKeySpec(keyBytes, 0, keyBytes.length, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(mode, sKeySpec, new IvParameterSpec(
                new byte[cipher.getBlockSize()]));
        changedData = cipher.doFinal(fileData);
        return changedData;
    }



    /**
     *
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param inputStreamOfFileToCode stream the the file you want te code
     * @param key the key used to do the coding
     * @param directoryToSaveFile the directory the file should be saved into after coding it
     * @param codedFileName
     * @return
     */
    public static File saveCodedFile(int mode, InputStream inputStreamOfFileToCode, String key, File directoryToSaveFile, String codedFileName){

        if(mode != Cipher.DECRYPT_MODE && mode != Cipher.ENCRYPT_MODE)
            throw new RuntimeException("Wrong usage of this methods signature! Use Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE!");

        File file;
        try {
            file = new File(directoryToSaveFile, codedFileName);
            BufferedOutputStream bos = new BufferedOutputStream(
                    new FileOutputStream(file));

            byte[] filesBytes;
            if(Cipher.ENCRYPT_MODE == mode)
                filesBytes = encodeFile(key, readBytes(inputStreamOfFileToCode));
            else
                filesBytes = decodeFile(key, readBytes(inputStreamOfFileToCode));
            bos.write(filesBytes);
            bos.flush();
            bos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return file;

    }


    // see https://stackoverflow.com/a/2436413/2418367
    private static byte[] readBytes(InputStream inputStream) throws IOException {
        // this dynamically extends to take the bytes you read
        ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();

        // this is storage overwritten on each iteration with bytes
        int bufferSize = 1024;
        byte[] buffer = new byte[bufferSize];

        // we need to know how may bytes were read to write them to the byteBuffer
        int len;
        while ((len = inputStream.read(buffer)) != -1) {
            byteBuffer.write(buffer, 0, len);
        }

        // and then we can return your byte array.
        return byteBuffer.toByteArray();
    }

    public static String getEncodedFileName(String plainFileName){
        return plainFileName+"-enc";
    }

    public static String getDecodedFileName(String encodedFileName){
        assert(encodedFileName.length() >= 6);
        return encodedFileName.substring(0,encodedFileName.length()-4);
    }

}
