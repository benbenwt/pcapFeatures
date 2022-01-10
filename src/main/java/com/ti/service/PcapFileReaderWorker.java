package com.ti.service;


import com.ti.utils.config.Utils;
import com.ti.utils.flow.BasicPacketInfo;
import com.ti.utils.flow.FlowFeature;
import com.ti.utils.flow.FlowGenerator;
import com.ti.utils.packet.PacketReader;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;



import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static com.ti.utils.config.Utils.*;


public class PcapFileReaderWorker{

    List<String> temps=new ArrayList<>();
    public static final String PROPERTY_FILE_CNT = "file_count";
    public static final String PROPERTY_CUR_FILE = "file_current";
    public static final String PROPERTY_FLOW = "file_flow";
    private static final String DividingLine = "---------------------------------------------------------------------------------------------------------------";

    private long flowTimeout;
    private long activityTimeout;
    private int     totalFlows = 0;

    private File pcapPath;
    private String outPutDirectory;
    private List<String> chunks;

    public PcapFileReaderWorker(File inputFile, String outPutDir) {
        super();
        pcapPath = inputFile;
        outPutDirectory = outPutDir;
        chunks = new ArrayList<>();

        if(!outPutDirectory.endsWith(FILE_SEP)) {
            outPutDirectory = outPutDirectory + FILE_SEP;
        }
        flowTimeout = 120000000L;
        activityTimeout = 5000000L;
    }

    public PcapFileReaderWorker(File inputFile, String outPutDir,long param1,long param2) {
        super();
        pcapPath = inputFile;
        outPutDirectory = outPutDir;
        chunks = new ArrayList<>();

        if(!outPutDirectory.endsWith(FILE_SEP)) {
            outPutDirectory = outPutDirectory + FILE_SEP;
        }
        flowTimeout = param1;
        activityTimeout = param2;
    }


    private void readPcapFileMy(String inputFile, String outPath) {
//        inputFile="C:\\Users\\guo\\Desktop\\pcapFeatures\\CICFlowMeter-master\\pcapTest\\2014-01-14-Magnitude-EK-traffic.pcap";
//        outPath="C:\\Users\\guo\\Desktop\\pcapFeatures\\CICFlowMeter-master\\pcapTest\\";
//        System.out.println("input: "+inputFile);
        if(inputFile==null ||outPath==null ) {
            return;
        }

        Path p = Paths.get(inputFile);
        String fileName = p.getFileName().toString();//FilenameUtils.getName(inputFile);

        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath+fileName+ Utils.FLOW_SUFFIX);

        if (saveFileFullPath.exists()) {
            if (!saveFileFullPath.delete()) {
                System.out.println("Saved file full path cannot be deleted");
            }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);

        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader;
        try {
             packetReader = new PacketReader(inputFile, readIP4, readIP6);

        }catch (NullPointerException e)
        {
            System.out.println(e);
            temps.add(inputFile);
            return;
        }

        while(true) {
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                if(basicPacket !=null){
                    flowGen.addPacketMy(basicPacket,outPath,fileName);
                }else{
                }
            }catch(PcapClosedException e){
                System.out.println(e);
                break;
            }
        }
        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());
    }

    public   void pcapDirectoryReaderWorker(String pcapDirStr,String savePathStr){
        File pcapDirFile=new File(pcapDirStr);
//        System.out.println(pcapDirFile.list().length);
        PcapFileReaderWorker pcapFileReaderWorker=new PcapFileReaderWorker(new File(""),"");
        for(String pcapFileString:pcapDirFile.list())
        {
            System.out.println("pcapFileString = "+pcapFileString);
            pcapFileReaderWorker.readPcapFileMy(pcapDirStr+File.separator+pcapFileString,savePathStr);
        }
    }
    public static void main(String[] args) {
        PcapFileReaderWorker pcapFileReaderWorker=new PcapFileReaderWorker(new File(""),"");
        pcapFileReaderWorker.readPcapFileMy(args[0],args[1]);
//        pcapFileReaderWorker.pcapDirectoryReaderWorker("D:\\pcapResult\\csv\\platformPcapFeatures\\pcap","D:\\pcapResult\\csv\\platformPcapFeatures\\features");
//        System.out.println(pcapFileReaderWorker.temps);
//        C:\Users\guo\Desktop\pcapFeatures\CICFlowMeter-master\pcapTest\2013-08-16-Styx-EK-traffic.pcap   C:\Users\guo\Desktop\pcapFeatures\CICFlowMeter-master\pcapTest
    }
}
