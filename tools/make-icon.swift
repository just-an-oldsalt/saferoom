// Draws the app icon: a dungeon safe room behind a stone arch.
//
//   swift tools/make-icon.swift <out.png>    (make icon runs this)

import AppKit

let S: CGFloat = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 1024, pixelsHigh: 1024, bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                           bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let cg = NSGraphicsContext.current!.cgContext
func c(_ h: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat(h >> 16 & 255) / 255, green: CGFloat(h >> 8 & 255) / 255, blue: CGFloat(h & 255) / 255, alpha: a)
}
func grad(_ path: CGPath, _ cols: [CGColor], from: CGPoint, to: CGPoint) {
    cg.saveGState(); cg.addPath(path); cg.clip()
    let g = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: cols as CFArray, locations: nil)!
    cg.drawLinearGradient(g, start: from, end: to, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    cg.restoreGState()
}

// Tile: macOS icon grid, 824 pt body with a soft shadow.
let tile = CGPath(roundedRect: CGRect(x: 100, y: 100, width: 824, height: 824), cornerWidth: 185, cornerHeight: 185, transform: nil)
cg.saveGState()
cg.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: c(0x000000, 0.45))
cg.addPath(tile); cg.setFillColor(c(0x1a1d2b)); cg.fillPath()
cg.restoreGState()
grad(tile, [c(0x2a2f45), c(0x14121f)], from: CGPoint(x: 512, y: 924), to: CGPoint(x: 512, y: 100))

cg.saveGState(); cg.addPath(tile); cg.clip()

// Dungeon floor.
cg.setFillColor(c(0x0d0b14)); cg.fill(CGRect(x: 100, y: 100, width: 824, height: 150))

// Stone arch: an outer arch filled with stones, an inner doorway cut out.
func arch(_ r: CGRect) -> CGPath {
    let p = CGMutablePath()
    let rad = r.width / 2
    p.move(to: CGPoint(x: r.minX, y: r.minY))
    p.addLine(to: CGPoint(x: r.minX, y: r.maxY - rad))
    p.addArc(center: CGPoint(x: r.midX, y: r.maxY - rad), radius: rad, startAngle: .pi, endAngle: 0, clockwise: true)
    p.addLine(to: CGPoint(x: r.maxX, y: r.minY))
    p.closeSubpath()
    return p
}
let outer = arch(CGRect(x: 250, y: 230, width: 524, height: 590))
let inner = arch(CGRect(x: 330, y: 230, width: 364, height: 500))
grad(outer, [c(0x8a8798), c(0x55525f)], from: CGPoint(x: 512, y: 820), to: CGPoint(x: 512, y: 230))
// Stone joints, a bit uneven on purpose.
cg.saveGState(); cg.addPath(outer); cg.clip()
cg.setStrokeColor(c(0x2e2c36)); cg.setLineWidth(9); cg.setLineCap(.round)
let center = CGPoint(x: 512, y: 548)
for a in stride(from: 0.0, through: 180.0, by: 22.5) {
    let t = CGFloat(a + (a == 90 ? 0 : (a < 90 ? 3 : -3))) * .pi / 180
    cg.move(to: CGPoint(x: center.x + cos(t) * 180, y: center.y + sin(t) * 180))
    cg.addLine(to: CGPoint(x: center.x + cos(t) * 270, y: center.y + sin(t) * 270))
}
for y in stride(from: 300.0, through: 520.0, by: 74.0) {
    for x in [250.0, 694.0] {
        cg.move(to: CGPoint(x: x, y: y)); cg.addLine(to: CGPoint(x: x + 80, y: y + 4))
    }
}
cg.strokePath()
cg.restoreGState()

// Warm light from inside the room.
cg.saveGState(); cg.addPath(inner); cg.clip()
cg.setFillColor(c(0xffd27a)); cg.fill(CGRect(x: 0, y: 0, width: S, height: S))
let glow = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: [c(0xfff3c4), c(0xffb347)] as CFArray, locations: nil)!
cg.drawRadialGradient(glow, startCenter: CGPoint(x: 512, y: 470), startRadius: 0, endCenter: CGPoint(x: 512, y: 470), endRadius: 300, options: [])
cg.restoreGState()

// The door, swung half open to the left: a skewed plank slab.
let door = CGMutablePath()
door.move(to: CGPoint(x: 330, y: 230))
door.addLine(to: CGPoint(x: 330, y: 730 - 182 + 182))
door.addLine(to: CGPoint(x: 330, y: 730))
door.addQuadCurve(to: CGPoint(x: 470, y: 690), control: CGPoint(x: 400, y: 745))
door.addLine(to: CGPoint(x: 470, y: 262))
door.closeSubpath()
grad(door, [c(0x8b5a2b), c(0x5a3415)], from: CGPoint(x: 330, y: 500), to: CGPoint(x: 470, y: 500))
cg.saveGState(); cg.addPath(door); cg.clip()
cg.setStrokeColor(c(0x3b210c)); cg.setLineWidth(6)
for x in stride(from: 365.0, through: 445.0, by: 38.0) { cg.move(to: CGPoint(x: x, y: 200)); cg.addLine(to: CGPoint(x: x, y: 760)) }
cg.strokePath()
cg.setFillColor(c(0x2b2b33))
cg.fill(CGRect(x: 320, y: 320, width: 160, height: 26))
cg.fill(CGRect(x: 320, y: 580, width: 160, height: 26))
cg.restoreGState()

// A green "SAFE ROOM" plaque over the arch, slightly crooked.
cg.saveGState()
cg.translateBy(x: 512, y: 840); cg.rotate(by: -0.035)
let plaque = CGPath(roundedRect: CGRect(x: -190, y: -42, width: 380, height: 84), cornerWidth: 14, cornerHeight: 14, transform: nil)
cg.setShadow(offset: .zero, blur: 30, color: c(0x5cff8a, 0.8))
cg.addPath(plaque); cg.setFillColor(c(0x123d22)); cg.fillPath()
cg.setShadow(offset: .zero, blur: 0, color: nil)
cg.addPath(plaque); cg.setStrokeColor(c(0x5cff8a)); cg.setLineWidth(7); cg.strokePath()
let text = NSAttributedString(string: "SAFE ROOM", attributes: [
    .font: NSFont.systemFont(ofSize: 52, weight: .black),
    .foregroundColor: NSColor(red: 0.62, green: 1, blue: 0.72, alpha: 1), .kern: 3])
let size = text.size()
text.draw(at: CGPoint(x: -size.width / 2, y: -size.height / 2 + 2))
cg.restoreGState()

// A little shield on the floor light: the "blocked" mark.
cg.saveGState()
cg.translateBy(x: 600, y: 300)
let shield = CGMutablePath()
shield.move(to: CGPoint(x: 0, y: 120))
shield.addQuadCurve(to: CGPoint(x: 95, y: 90), control: CGPoint(x: 50, y: 120))
shield.addQuadCurve(to: CGPoint(x: 0, y: -105), control: CGPoint(x: 100, y: -40))
shield.addQuadCurve(to: CGPoint(x: -95, y: 90), control: CGPoint(x: -100, y: -40))
shield.addQuadCurve(to: CGPoint(x: 0, y: 120), control: CGPoint(x: -50, y: 120))
cg.setShadow(offset: CGSize(width: 0, height: -8), blur: 16, color: c(0x000000, 0.6))
cg.addPath(shield); cg.setFillColor(c(0x2b6cff)); cg.fillPath()
cg.setShadow(offset: .zero, blur: 0, color: nil)
grad(shield, [c(0x5a8cff), c(0x1d3fb0)], from: CGPoint(x: 0, y: 120), to: CGPoint(x: 0, y: -105))
cg.addPath(shield); cg.setStrokeColor(c(0xdfe8ff)); cg.setLineWidth(9); cg.strokePath()
// A no-sign slash ring.
cg.setStrokeColor(c(0xffffff)); cg.setLineWidth(16)
cg.strokeEllipse(in: CGRect(x: -45, y: -35, width: 90, height: 90))
cg.move(to: CGPoint(x: -30, y: -20)); cg.addLine(to: CGPoint(x: 30, y: 40)); cg.strokePath()
cg.restoreGState()

cg.restoreGState()
// Thin highlight on the tile edge.
cg.addPath(tile); cg.setStrokeColor(c(0xffffff, 0.08)); cg.setLineWidth(3); cg.strokePath()

NSGraphicsContext.current = nil
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
