/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static java.util.Comparator.comparing;
import static org.springframework.http.MediaType.ALL_VALUE;

import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.TimeZone;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

/** Controller for uploading a file */
@Controller
@Slf4j
public class FileServer {

  private static final DateTimeFormatter dateTimeFormatter =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  @Value("${webwolf.fileserver.location}")
  private String fileLocation;

  @Value("${server.address}")
  private String server;

  @Value("${server.servlet.context-path}")
  private String contextPath;

  @Value("${server.port}")
  private int port;

  @RequestMapping(
      path = "/file-server-location",
      consumes = ALL_VALUE,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String getFileLocation() {
    return fileLocation;
  }

  @PostMapping(value = "/fileupload")
  public ModelAndView importFile(
      @RequestParam("file") MultipartFile multipartFile, Authentication authentication)
      throws IOException {
    var username = authentication.getName();
    var destinationDir = new File(fileLocation, username);
    destinationDir.mkdirs();

    /*
     * The name comes from the upload, so it decides nothing about where the file lands. Resolving
     * it as given let "../" walk out of the caller's own directory, and since the destination is
     * deleted before it is written that reached both any file this process may write and any file
     * it may remove. The name is reduced to its last segment and the resolved location has to sit
     * directly inside the caller's directory before anything is touched.
     */
    var safeName = safeFileName(multipartFile.getOriginalFilename());
    if (safeName == null) {
      return rejectedUpload();
    }
    var destinationFile = destinationDir.toPath().resolve(safeName);
    var resolvedParent = destinationFile.toFile().getCanonicalFile().getParentFile();
    if (resolvedParent == null || !resolvedParent.equals(destinationDir.getCanonicalFile())) {
      return rejectedUpload();
    }

    // DO NOT use multipartFile.transferTo(), see
    // https://stackoverflow.com/questions/60336929/java-nio-file-nosuchfileexception-when-file-transferto-is-called
    try (InputStream is = multipartFile.getInputStream()) {
      Files.deleteIfExists(destinationFile);
      Files.copy(is, destinationFile);
    }
    log.debug("File saved to {}", destinationFile);

    return new ModelAndView(
        new RedirectView("files", true),
        new ModelMap().addAttribute("uploadSuccess", "File uploaded successful"));
  }

  /** The bare file name the upload asked for, or null when nothing usable is left of it. */
  private static String safeFileName(String requestedName) {
    if (requestedName == null) {
      return null;
    }
    var candidate = FilenameUtils.getName(requestedName.replace('\\', '/'));
    if (candidate == null || candidate.isBlank() || ".".equals(candidate)) {
      return null;
    }
    return "..".equals(candidate) ? null : candidate;
  }

  private ModelAndView rejectedUpload() {
    return new ModelAndView(
        new RedirectView("files", true),
        new ModelMap().addAttribute("uploadSuccess", "That file name is not accepted"));
  }

  @GetMapping(value = "/files")
  public ModelAndView getFiles(
      HttpServletRequest request, Authentication authentication, TimeZone timezone) {
    String username = (null != authentication) ? authentication.getName() : "anonymous";
    File destinationDir = new File(fileLocation, username);

    ModelAndView modelAndView = new ModelAndView();
    modelAndView.setViewName("files");
    File changeIndicatorFile = new File(destinationDir, username + "_changed");
    if (changeIndicatorFile.exists()) {
      modelAndView.addObject("uploadSuccess", request.getParameter("uploadSuccess"));
    }
    changeIndicatorFile.delete();

    record UploadedFile(String name, String size, String link, String creationTime) {}

    var uploadedFiles = new ArrayList<UploadedFile>();
    File[] files = destinationDir.listFiles(File::isFile);
    if (files != null) {
      for (File file : files) {
        String size = FileUtils.byteCountToDisplaySize(file.length());
        String link = String.format("files/%s/%s", username, file.getName());
        uploadedFiles.add(
            new UploadedFile(file.getName(), size, link, getCreationTime(timezone, file)));
      }
    }

    modelAndView.addObject(
        "files",
        uploadedFiles.stream().sorted(comparing(UploadedFile::creationTime).reversed()).toList());
    modelAndView.addObject("webwolf_url", "http://" + server + ":" + port + contextPath);
    return modelAndView;
  }

  private String getCreationTime(TimeZone timezone, File file) {
    try {
      FileTime creationTime = (FileTime) Files.getAttribute(file.toPath(), "creationTime");
      ZonedDateTime zonedDateTime = creationTime.toInstant().atZone(timezone.toZoneId());
      return dateTimeFormatter.format(zonedDateTime);
    } catch (IOException e) {
      return "unknown";
    }
  }
}
