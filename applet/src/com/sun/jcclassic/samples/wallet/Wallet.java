/** 
 * Copyright (c) 1998, 2017, Oracle and/or its affiliates. All rights reserved.
 * 
 */

/*
 */

/*
 * @(#)Wallet.java	1.11 06/01/03
 */

package com.sun.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.JCSystem;

public class Wallet extends Applet {

	/* constants declaration */

	// code of CLA byte in the command APDU header
	final static byte Wallet_CLA = (byte) 0x80;

	// codes of INS byte in the command APDU header
	final static byte VERIFY = (byte) 0x20;
	final static byte CREDIT = (byte) 0x30;
	final static byte DEBIT = (byte) 0x40;
	final static byte GET_BALANCE = (byte) 0x50;
	final static byte UPDATE_PIN = (byte) 0x70;

	// maximum balance
	final static short MAX_BALANCE = 10000;
	// maximum transaction amount
	final static short MAX_TRANSACTION_AMOUNT = 1000;

	// maximum number of incorrect tries before the
	// PIN is blocked
	final static byte PIN_TRY_LIMIT = (byte) 0x03;
	// maximum size PIN
	static short UPDATE_TRY_LIMIT = (byte) 0x03;
	final static byte MAX_PIN_SIZE = (byte) 0x08;

	// signal that the PIN verification failed
	final static short SW_VERIFICATION_FAILED = 0x6300;
	// signal the the PIN validation is required
	// for a credit or a debit transaction
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	// signal invalid transaction amount
	// amount > MAX_TRANSACTION_AMOUNT or amount < 0
	final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

	// signal that the balance exceed the maximum
	final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
	// signal the the balance becomes negative
	final static short SW_NEGATIVE_BALANCE = 0x6A85;

	static final short SW_SECURITY_STATUS_NOT_SATISFIED = 0x6A86;

	/* instance variables declaration */
	OwnerPIN pin;
	short balance;
	short loyaltyPoints;

	final static short MAX_LOYALTY_POINTS = 300;

	private Wallet(byte[] bArray, short bOffset, byte bLength) {

		// It is good programming practice to allocate
		// all the memory that an applet needs during
		// its lifetime inside the constructor
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

		byte iLen = bArray[bOffset]; // aid length
		bOffset = (short) (bOffset + iLen + 1);
		byte cLen = bArray[bOffset]; // info length
		bOffset = (short) (bOffset + cLen + 1);
		byte aLen = bArray[bOffset]; // applet data length

		// The installation parameters contain the PIN
		// initialization value
		pin.update(bArray, (short) (bOffset + 1), aLen);
		register();

	} // end of the constructor

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// create a Wallet applet instance
		new Wallet(bArray, bOffset, bLength);
	} // end of install method

	@Override
	public boolean select() {

		// The applet declines to be selected
		// if the pin is blocked.
		if (pin.getTriesRemaining() == 0) {
			return false;
		}

		return true;

	}// end of select method

	@Override
	public void deselect() {
		// reset the pin value
		pin.reset();
	}

	@Override
	public void process(APDU apdu) {

		// APDU object carries a byte array (buffer) to
		// transfer incoming and outgoing APDU header
		// and data bytes between card and CAD

		// At this point, only the first header bytes
		// [CLA, INS, P1, P2, P3] are available in
		// the APDU buffer.
		// The interface javacard.framework.ISO7816
		// declares constants to denote the offset of
		// these bytes in the APDU buffer

		byte[] buffer = apdu.getBuffer();
		// check SELECT APDU command

		if (apdu.isISOInterindustryCLA()) {
			if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
				return;
			}
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		// verify the reset of commands have the
		// correct CLA byte, which specifies the
		// command structure
		if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		case GET_BALANCE:
			getBalance(apdu);
			return;
		case DEBIT:
			debit(apdu);
			return;
		case CREDIT:
			credit(apdu);
			return;
		case VERIFY:
			verify(apdu);
			return;
		case UPDATE_PIN:
			updatePIN(apdu);
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

	} // end of process method

	private void credit(APDU apdu) {

		// access authentication
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}

		byte[] buffer = apdu.getBuffer();

		// Lc byte denotes the number of bytes in the
		// data field of the command APDU
		byte numBytes = buffer[ISO7816.OFFSET_LC];

		// indicate that this APDU has incoming data
		// and receive data starting from the offset
		// ISO7816.OFFSET_CDATA following the 5 header
		// bytes.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// it is an error if the number of data bytes
		// read does not match the number in Lc byte
		if ((numBytes != 2) || (byteRead != 2)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// get the credit amount
		short creditAmount = createShort(buffer[ISO7816.OFFSET_CDATA], buffer[ISO7816.OFFSET_CDATA + 1]);

		// check the credit amount
		if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}

		// check the new balance
		if ((short) (balance + creditAmount) > MAX_BALANCE) {
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
		}

		// credit the amount
		balance = (short) (balance + creditAmount);

	} // end of deposit method

	private void debit(APDU apdu) {

		// access authentication
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}

		byte[] buffer = apdu.getBuffer();
		byte numBytes = (buffer[ISO7816.OFFSET_LC]);
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// metoda de plata e stocata in variabila p1
		byte p1 = buffer[ISO7816.OFFSET_P1];

		if (p1 == 2) {
			if ((numBytes != 4) || (byteRead != 4))
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		} else if (p1 == 1 || p1 == 0) {
			if ((numBytes != 2) || (byteRead != 2))
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// get debit amount
		short debitAmount = createShort(buffer[ISO7816.OFFSET_CDATA], buffer[ISO7816.OFFSET_CDATA + 1]);
		// check debit amount
		if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}

		switch (p1) {
		case 0: // doar bani
			// check the new balance
			if ((short) (balance - debitAmount) < (short) 0)
				ISOException.throwIt(SW_NEGATIVE_BALANCE);

			JCSystem.beginTransaction();
			balance = (short) (balance - debitAmount);
			loyaltyPoints += debitAmount / 10;
			if (loyaltyPoints > MAX_LOYALTY_POINTS)
				loyaltyPoints = MAX_LOYALTY_POINTS;
			JCSystem.commitTransaction();

			break;

		case 1:
			// doar puncte
			if (loyaltyPoints < debitAmount)
				ISOException.throwIt(SW_NEGATIVE_BALANCE);
			loyaltyPoints -= debitAmount;
			break;

		case 2: // bani si puncte
			// byte 3 si byte 4 din data reprezinta ce suma va fi platita cu
			// puncte
			short pointsDebitAmount = createShort(buffer[ISO7816.OFFSET_CDATA + 2], buffer[ISO7816.OFFSET_CDATA + 3]);
			// verificari
			if (loyaltyPoints < pointsDebitAmount)
				ISOException.throwIt(SW_NEGATIVE_BALANCE);
			if ((short) (pointsDebitAmount + balance - debitAmount) < (short) 0)
				ISOException.throwIt(SW_NEGATIVE_BALANCE);
			//
			JCSystem.beginTransaction();
			loyaltyPoints -= pointsDebitAmount;
			balance -= (debitAmount - pointsDebitAmount);
			loyaltyPoints += (short) (debitAmount - pointsDebitAmount) / 10;
			JCSystem.commitTransaction();
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
	} // end of debit method

	private void getBalance(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		byte p1 = buffer[ISO7816.OFFSET_P1];

		if (p1 > 2)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		// inform system that the applet has finished
		// processing the command and the system should
		// now prepare to construct a response APDU
		// which contains data field
		short le = apdu.setOutgoing();

		if (le < 2) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// informs the CAD the actual number of bytes
		// returned
		apdu.setOutgoingLength((byte) 2);

		// move the balance data into the APDU buffer
		// starting at the offset 0
		switch (p1) {
		case (byte) 0:
			JCSystem.beginTransaction();
			buffer[0] = (byte) (balance >> 8);
			buffer[1] = (byte) (balance & 0xFF);
			JCSystem.commitTransaction();
			break;
		case (byte) 1:
			JCSystem.beginTransaction();
			buffer[0] = (byte) (loyaltyPoints >> 8);
			buffer[1] = (byte) (loyaltyPoints & 0xFF);
			JCSystem.commitTransaction();
			break;
		case (byte) 2:
			JCSystem.beginTransaction();
			buffer[0] = (byte) (balance >> 8);
			buffer[1] = (byte) (balance & 0xFF);
			buffer[2] = (byte) (loyaltyPoints >> 8);
			buffer[3] = (byte) (loyaltyPoints & 0xFF);
			JCSystem.commitTransaction();
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			break;
		}
		// send the 2-byte balance at the offset
		// 0 in the apdu buffer
		apdu.sendBytes((short) 0, (short) 2);

	} // end of getBalance method

	private void verify(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		// retrieve the PIN data for validation.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// check pin
		// the PIN data is read into the APDU buffer
		// at the offset ISO7816.OFFSET_CDATA
		// the PIN data length = byteRead
		if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		}

	} // end of validate method

	private void updatePIN(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		byte pinLenght = buffer[ISO7816.OFFSET_CDATA];

		if (pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinLenght) == false) {
			UPDATE_TRY_LIMIT--;
			if (UPDATE_TRY_LIMIT == 0) {
				ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
			}
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		}
		byte newPinLenght = buffer[(short) (ISO7816.OFFSET_CDATA + pinLenght + 1)];
		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 2 + pinLenght), newPinLenght);
	}

	private short createShort(byte b1, byte b2) {
		return (short) ((b1 & 0xff) << 8 | (b2 & 0xff));
	}
} // end of class Wallet