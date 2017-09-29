package de.kruegersolutions.butlerssecretplugin;

import android.app.IntentService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.v4.content.FileProvider;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;

import javax.crypto.Cipher;

import de.kruegersolutions.butlerssecretplugin.cryption.Utils;

/**
 * This plugin realises encryption for sending a shot
 *
 *
 */
public class EnigmaService extends IntentService {

    private static final String TAG = EnigmaService.class.getSimpleName();
    private static final boolean DEBUG = true;


    // this will be inserted into the intent to check if an encrypting plugin is installed
    private static final String ACTION_PING = "de.kruegersolutions.ACTION_PING";
    // the plugin has to respond with a pong to the checking ping
    private static final String ACTION_PONG = "de.kruegersolutions.ACTION_PONG";


    // An intent with this action tells the plugin to decode the (encoded) file in the data (as uri) of the intent.
    private static final String ACTION_DECODE = "de.kruegersolutions.ACTION_DECODE";
    // An intent with this action tells the plugin to encode the (plain) file in the data (as uri) of the intent.
    private static final String ACTION_ENCODE = "de.kruegersolutions.ACTION_ENCODE";
    // An intent with this action tells the butler, that the plugin did its job and decoded the file and attached it (as uri) in the data of the returning intent.
    private static final String ACTION_DECODED = "de.kruegersolutions.ACTION_DECODED";
    // An intent with this action tells the butler, that the plugin did its job and encoded the file and attached it (as uri) in the data of the returning intent.
    private static final String ACTION_ENCODED = "de.kruegersolutions.ACTION_ENCODED";

    // these constants are used to find/put the needed values in the extras of the intent
    private static final String EXTRA_PARAM_SYMMETRIC_KEY = "de.kruegersolutions.FOTO_BUTLER_EXTRA_PARAM_SYMMETRIC_KEY";
    //public static final String EXTRA_PARAM_ALGORITHM = "de.kruegersolutions.FOTO_BUTLER_EXTRA_PARAM_ALGORITHM";
    private static final String EXTRA_PARAM_FILE_NAME = "de.kruegersolutions.FOTO_BUTLER_EXTRA_PARAM_FILE_NAME";

    // whenever any step fails here, the butler needs an answer, so he can react. Put this flag into the intent
    private static final String EXTRA_PARAM_FLAG_FAILED = "de.kruegersolutions.FOTO_BUTLER_EXTRA_PARAM_FLAG_FAILED";

    // these hooks into the butler should not be changed
    private static final String SERVICE_TO_RESPOND = "de.kruegersolutions.fotobutler.helper.EnigmaService";
    private static final String PACKAGE_TO_RESPOND = "de.kruegersolutions.fotobutler";



    public EnigmaService() {
        super("EnigmaService");
    }



    @Override
    protected void onHandleIntent(Intent intent){
        String action = intent.getAction();
        if(DEBUG) Log.d(TAG, "Caught an intent with action "+ action);

        // clear the private folder (will contain old files from the coding of the last call)
        //Utils.clearFilesDir(context);

        if(ACTION_PING.equals(action)){
            Intent responseIntent = new Intent();
            responseIntent.setAction(ACTION_PONG);
            responseIntent.setComponent(new ComponentName(PACKAGE_TO_RESPOND, SERVICE_TO_RESPOND));
            startService(responseIntent);
            if(DEBUG) Log.d(TAG, "Got a Ping, responded with Pong!");
        }

        if(ACTION_ENCODE.equals(action)){
            if(DEBUG) Log.d(TAG, "Caught a broadcast to encode a file!");
            handleCoding(this, intent, Cipher.ENCRYPT_MODE);
        }

        if(ACTION_DECODE.equals(action)){
            if(DEBUG) Log.d(TAG, "Caught a broadcast to decode a file!");
            handleCoding(this, intent, Cipher.DECRYPT_MODE);
        }
    }


    /**
     * This method is used to lift the work. We get the reading permission from the butler to the file
     * (delivered as uri). We store the newly generated file (en-/decoded, as requested) in the
     * package directory of this plugin and grant permissions again to the butler.
     * @param context the context we work with
     * @param intent the incoming intent, which stores all the values we need to do our work
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     */
    private void handleCoding(Context context, Intent intent, int mode) {

        if(mode != Cipher.DECRYPT_MODE && mode != Cipher.ENCRYPT_MODE)
            throw new RuntimeException("Wrong usage of this methods signature! Use Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE!");

        // extract data to encode
        final String key = intent.getStringExtra(EXTRA_PARAM_SYMMETRIC_KEY);
        final Uri fileURI = intent.getData();
        InputStream inputFileInputStream = null;
        try {
            inputFileInputStream = context.getContentResolver().openInputStream(fileURI);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            // we got an error - inform the butler he wont get a result from us
            Intent responseIntent = new Intent();
            responseIntent.setAction(mode==Cipher.DECRYPT_MODE ? ACTION_DECODED : ACTION_ENCODED);
            responseIntent.putExtra(EXTRA_PARAM_FLAG_FAILED, true);
            responseIntent.setComponent(new ComponentName(PACKAGE_TO_RESPOND, SERVICE_TO_RESPOND));
            startService(responseIntent);


            if(DEBUG) Log.d(TAG, "Broadcasted an intent (to the butler) with extra_param_flag_failed in it.");
            return;
        }

        final String inputFileName = intent.getStringExtra(EXTRA_PARAM_FILE_NAME);
        final String pictureType = inputFileName.substring(inputFileName.lastIndexOf('.')+1);
        final String outputFileName;
        if(Cipher.ENCRYPT_MODE == mode){
            outputFileName = Utils.getEncodedFileName(inputFileName);
        } else {
            outputFileName = Utils.getDecodedFileName(inputFileName);
        }


        //final File directoryForOutputFile = new File(context.getFilesDir(), "temp");
        final File directoryForOutputFile = context.getFilesDir();
        if(DEBUG) Log.d(TAG, "#1 "+directoryForOutputFile+"  isDir?="+directoryForOutputFile.isDirectory()+"  exists?="+directoryForOutputFile.exists()+"   readable?="+directoryForOutputFile.canRead());
        if(!directoryForOutputFile.isDirectory())
            //noinspection ResultOfMethodCallIgnored
            directoryForOutputFile.mkdirs();
        if(DEBUG) Log.d(TAG, "#2 "+directoryForOutputFile+"  isDir?="+directoryForOutputFile.isDirectory()+"  exists?="+directoryForOutputFile.exists()+"   readable?="+directoryForOutputFile.canRead());

        final File outputFile;
        outputFile = Utils.saveCodedFile(mode, inputFileInputStream, key, directoryForOutputFile, outputFileName);

        Intent respondIntent = new Intent();

        if(Cipher.ENCRYPT_MODE == mode){
            respondIntent.setAction(ACTION_ENCODED);
        } else {
            respondIntent.setAction(ACTION_DECODED);
        }


        if(outputFile == null){
            respondIntent.putExtra(EXTRA_PARAM_FLAG_FAILED, true);
            if(DEBUG) Log.d(TAG, "Something went wrong coding "+inputFileName+". Added the failed-flag to the broadcast to send.");
        } else {
            Uri uri = FileProvider.getUriForFile(context,
                    BuildConfig.APPLICATION_ID + ".provider", outputFile);
            // fixme: hack so far (one should be sufficent) (this or the flags - but unfortunately it is not for my Galaxy S4)
            context.grantUriPermission("de.kruegersolutions.fotobutler", uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
            respondIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            respondIntent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            respondIntent.setDataAndType(uri, "image/"+pictureType+"-enc");
            respondIntent.putExtra(EXTRA_PARAM_FILE_NAME, outputFileName);
        }

        respondIntent.setComponent(new ComponentName(PACKAGE_TO_RESPOND, SERVICE_TO_RESPOND));
        startService(respondIntent);

        // delete the incoming file
        context.getContentResolver().delete(fileURI, null, null);


        // fixme: get rid of the file dump, when handled the deleting files problem
        if(DEBUG){
            String stMode;
            if(Cipher.ENCRYPT_MODE == mode)
                stMode = "Encoded";
            else stMode = "Decoded";
            Log.d(TAG, stMode+" the file "+inputFileName+" into "+outputFileName+". Send corresponding broadcast (to the Butler).");
            Log.d(TAG, "Coded the type: >"+pictureType+"<");
            // list all the file in our private folder (see https://stackoverflow.com/a/11872389/2418367 )
            File dirFiles = context.getFilesDir();
            for (String strFile : dirFiles.list()){
                Log.d(TAG, "File in private Folder: >"+strFile+"<");
            }
        }
    }

}
