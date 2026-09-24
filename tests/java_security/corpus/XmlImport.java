package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;

public class XmlImport {
    Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        return f.newDocumentBuilder().parse(in);
    }

    void unzip(Path zip, Path dest) throws IOException {
        try (ZipInputStream z = new ZipInputStream(Files.newInputStream(zip))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                Path target = dest.resolve(e.getName()).normalize();
                if (!target.startsWith(dest)) throw new IOException("bad entry");
                Files.copy(z, target);
            }
        }
    }

    void runReport(String reportName) throws Exception {
        new ProcessBuilder("/usr/bin/report-gen", "--format", "pdf").start();
    }
}
