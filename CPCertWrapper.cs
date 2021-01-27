using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Wrap
{
    public class CPCert
    { 
        [DllImport("cpcert.dll", CallingConvention = CallingConvention.StdCall, EntryPoint = "unpack_zip_stream_container", CharSet = CharSet.Ansi)]
        public static extern int UnPackZipContainer(byte[] in_buf, Int64 size,out IntPtr alloc_buffer,out Int32 buf_size, string zip_passw, string secret);
        [DllImport("cpcert.dll", CallingConvention = CallingConvention.StdCall,EntryPoint = "free_heap", CharSet = CharSet.Ansi)]
        public static extern void FreeHeap(ref IntPtr alloc_ptr);

        public static string GetPemFromZipContainer(byte[] zip, string password, string secretkey, ref int err)
        {
            Int32 size_buffer;
            err = UnPackZipContainer(zip, zip.Length, out IntPtr buffer, out size_buffer, password, secretkey );
            string pem_string = Marshal.PtrToStringAnsi(buffer, (int)size_buffer);
            FreeHeap(buffer);
            return pem_string;
        }
    }

}   
 
