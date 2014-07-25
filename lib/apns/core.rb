module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195
  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
  @pems = nil # this should be a hash of target devices and paths of pem files, not pem's contents
  @passes = nil

  class << self
    attr_accessor :host, :pems, :port, :passes
  end

  def self.send_notification(device_token, message, target)
    n = APNS::Notification.new(device_token, message)
    self.send_notifications([n], target)
  end

  def self.send_notifications(notifications, target)
    raise "The path to your pem file is not set. (APNS.pems = { target1: '/path/to/cert1.pem', target2: '/path/to/cert2.pem' }" unless self.pems
    raise "The path to your #{target} pem file does not exist!" unless File.exist?(self.pems[target])

    sock, ssl = self.open_connection(self.pems[target], self.passes[target], self.host, self.port)

    packed_nofications = self.packed_nofications(notifications)

    notifications.each { |n| ssl.write(packed_nofications) }

    ssl.close
    sock.close
  end

  def self.packed_nofications(notifications)
    bytes = ''

    notifications.each do |notification|
      # Each notification frame consists of
      # 1. (e.g. protocol version) 2 (unsigned char [1 byte]) 
      # 2. size of the full frame (unsigend int [4 byte], big endian)
      pn = notification.packaged_notification
      bytes << ([2, pn.bytesize].pack('CN') + pn)
    end

    bytes
  end

  # def self.feedback
  #   sock, ssl = self.feedback_connection
  #
  #   apns_feedback = []
  #
  #   while message = ssl.read(38)
  #     timestamp, token_size, token = message.unpack('N1n1H*')
  #     apns_feedback << [Time.at(timestamp), token]
  #   end
  #
  #   ssl.close
  #   sock.close
  #
  #   return apns_feedback
  # end

  protected

  def self.open_connection(pem, pass, host, port)
    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(pem), pass)

    sock         = TCPSocket.new(host, port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end

  # def self.feedback_connection(pem, pass, host, port)
  #   context      = OpenSSL::SSL::SSLContext.new
  #   context.cert = OpenSSL::X509::Certificate.new(File.read(pem))
  #   context.key  = OpenSSL::PKey::RSA.new(File.read(pem), pass)
  #
  #   fhost = self.host.gsub('gateway','feedback')
  #   puts fhost
  #
  #   sock         = TCPSocket.new(fhost, 2196)
  #   ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
  #   ssl.connect
  #
  #   return sock, ssl
  # end
end
