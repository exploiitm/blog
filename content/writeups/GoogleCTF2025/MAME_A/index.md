+++
title = "MAME A"
date = 2025-08-07
authors = ["Aditya Sharma"]
+++
## Context

This challenge involves running a video game ROM on an emulator, I'll give a little bit of context for the people who don't mess around with emulators and emulation in general.

"The **Sega Genesis**, known as the **Mega Drive** outside North America, is a 16-bit console developed and sold by Sega.", 16-bit refers to the word-length of the main processor of the console, i.e. what is the number of bits which it can work with at a time.

MAME stands for Multiple Arcade Machine Emulator. **Emulation** is the process of imitating the behaviour of one computer system (the _guest_ system) using another (the _host_ system), allowing software designed for the original system to run on new, often very different, hardware.

For the layman an emulator isn't different from a compatibility layer for older hardware (often, gaming consoles)
# The Challenge
You're given a SEGA genesis ROM which is meant to be run on the MAME emulator.
![](attachments/Pasted%20image%2020250722132035.png)

You're provided a SEGA Genesis ROM written in rust and you're given the source code of the rom to do whatever you want with. The aim of the challenge is for you to get the player to two locations which contain flags on the map. The game itself is a Sonic the Hedgehog inspired platformer.

The challenge requires you to record your inputs in the game and send them over so that the checker can execute those movements on the server and check if you got the flags in game. What this means is that you have to get the flags in the actual game and not mod the ROM into getting you the flag.

The ROM is ran using the MAME emulator by running MAME and then navigating to and selecting the sonk.md file.

When you start, you're greeted by sonk the rabbit. The game itself contains obstacles like wasps and spikes.
![](attachments/Pasted%20image%2020250723115636.png) 
a wasp (waowaowao :3)

The aim of this challenge is to navigate to this flag here, 
![](attachments/Pasted%20image%2020250723115441.png)

# The Solution

While the way I solved it is more from intuition about how old games work, someone without the same knowledge as me wouldn't have a hard time coming to the same solution.

```rust
// this is a snippet from game/src/sonk.rs
pub fn update(&mut self) {

    self.controller.update();

    if let Some(scene) = self.win_scene.as_mut() {

        scene.update();

    } else {

        self.frame = self.frame.wrapping_add(1);

        self.sonk

            .update(&self.map, &mut self.vdp, &mut self.controller, self.frame);

        self.wasps

            .retain(|w| Wasp::on_screen(w.sprite.x as i16, w.sprite.y as i16));

        self.spikes

            .retain(|w| Spike::on_screen(w.sprite.x as i16, w.sprite.y as i16));

        for flag in &mut self.flags.iter_mut() {

            if flag.update(&self.sonk, self.frame) {

                self.win_scene = Some(YouWin::new(flag.id, &mut self.vdp));

                return;

            }

        }

        for wasp in &mut self.wasps.iter_mut() {

            wasp.update(&mut self.sonk);

        }

        for spike in &mut self.spikes.iter_mut() {

            spike.update(&mut self.sonk, self.frame);

        }

        self.update_camera();

    }

}

pub fn draw(&mut self) {

    self.renderer.clear();

    if let Some(scene) = self.win_scene.as_mut() {

        scene.render(&mut self.vdp);

    } else {

        self.sonk.render(self.frame, &mut self.renderer);

        for flag in &mut self.flags.iter_mut() {

            flag.render(&mut self.renderer);

        }

        for wasp in &mut self.wasps.iter_mut() {

            wasp.render(&mut self.renderer);

        }

        for spike in &mut self.spikes.iter_mut() {

            spike.render(&mut self.renderer);

        }

    }

  

    self.renderer.render(&mut self.vdp);

  

    // vsync

    self.vdp.wait_for_vblank();

}
```

These two methods update which sprites to render, and what it means is that the only sprites which will be rendered are the ones which are in view of the camera.

Since the only sprites being rendered are the ones within the view of the camera, if it were somehow possible to move sonk outside of where the camera is looking at, you would be able to just walk through where the spikes were supposed to be and get the flag by rendering the flag again.

The problem is that if you can't walk off the screen, the camera follows you everywhere, however you can knock yourself back out of the frame, there is a conveniently placed wasp right next to the spikes, by first unloading the spikes by walking off to the right, then positioning ourself such that we get knocked-back beyond the spikes, we can simply walk into flag A.
![](attachments/solngif.gif)

by running the emulator with `mame -record`, you can output your recorded input to a .inp file, which you then send over to the challenge and get your flag.
