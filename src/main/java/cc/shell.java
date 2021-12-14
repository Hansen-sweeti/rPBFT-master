package cc;

import lombok.SneakyThrows;
import org.apache.log4j.Logger;

import java.io.File;

public class shell {
    private static Logger logger = Logger.getLogger(shell.class);
    /**   *    * @param shPath  需要执行的命令或脚本路径   * @return   */
    @SneakyThrows
    public static void excute(String shPath){   String result="";
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder
                .command("bash", "test.sh")
                .directory(new File("C:\\Users\\ASUS\\Desktop\\pbft\\pbft-master\\src"));
        Process process = processBuilder.start();
    }
    /**   * 测试代码   * @param args   */
    public static void main(String[] args) {
        //执行windows 宽带连接命令
        //shell.excute("rasdial.exe 宽带连接 13900000000 111111");   //执行shell脚本
        shell.excute("C:\\Users\\ASUS\\Desktop\\pbft\\pbft-master\\src");  }


}
