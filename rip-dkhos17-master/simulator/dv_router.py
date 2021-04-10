"""
Your awesome Distance Vector router for CS 168
"""
import sys
import Queue as Q
import sim.api as api
import sim.basics as basics


# We define infinity as a distance of 16.
INFINITY = 16
EXPIRE_TIME = 15

class DVRouter (basics.DVRouterBase):
  NO_LOG = True # Set to True on an instance to disable its logging
  POISON_MODE = True # Can override POISON_MODE here
  DEFAULT_TIMER_INTERVAL = 5 # Can override this yourself for testing

  def __init__ (self):
    """
    Called when the instance is initialized.

    You probably want to do some additional initialization here.
    """
    self.DP = dict()
    self.timer = dict()
    self.weights = dict()
    self.start_timer() # Starts calling handle_timer() at correct rate

  def handle_link_up (self, port, latency):
    """
    Called by the framework when a link attached to this Entity goes up.

    The port attached to the link and the link latency are passed in.
    """
    self.weights[port] = latency
    

  def handle_link_down (self, port):
    """
    Called by the framework when a link attached to this Entity does down.

    The port number used by the link is passed in.
    """
    if port in self.weights:
      del self.weights[port]

    for destination, value in self.DP.items():
      if value[0] == port:
        del self.DP[destination]
        if self.POISON_MODE:
          self.send(basics.RoutePacket(destination, INFINITY), port, flood=True)
    

  def handle_rx (self, packet, port):
    """
    Called by the framework when this Entity receives a packet.

    packet is a Packet (or subclass).
    port is the port number it arrived on.

    You definitely want to fill this in.
    """
    self.log("RX %s on %s (%s)", packet, port, api.current_time())
    if isinstance(packet, basics.RoutePacket):
      new_latency = packet.latency + self.weights[port]
      
      if new_latency >= INFINITY:
        if packet.destination in self.DP and self.DP[packet.destination][0] == port:
          del self.DP[packet.destination]
          if self.POISON_MODE:
            self.send(basics.RoutePacket(packet.destination, INFINITY), port, flood=True)

      elif packet.destination not in self.DP or self.DP[packet.destination][1] >= new_latency or self.DP[packet.destination][0] == port:
        self.DP[packet.destination] = (port, new_latency)
        self.timer[packet.destination] = api.current_time()
        self.send(basics.RoutePacket(packet.destination, new_latency), port, flood=True)  

    elif isinstance(packet, basics.HostDiscoveryPacket):
      self.DP[packet.src] = (port, self.weights[port])
      self.timer[packet.src] = api.current_time()

    elif packet.dst in self.DP:
      self.send(packet, self.DP[packet.dst][0])

  def handle_timer (self):
    """
    Called periodically.

    When called, your router should send tables to neighbors.  It also might
    not be a bad place to check for whether any entries have expired.
    """
    for destination, port_latency in self.DP.items():
      if port_latency[0] not in self.weights: del self.DP[destination]
      elif port_latency[0] in self.weights or (api.current_time() - self.timer[destination] <= EXPIRE_TIME): 
        self.send(basics.RoutePacket(destination, port_latency[1]), flood=True)

