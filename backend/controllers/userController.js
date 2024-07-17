import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import User from '../models/userModel.js';
import generateTokenAndSetCookie from '../utils/helpers/generateTokenAndSetCookies.js';

export const signupUser = async (req, res) => {
	try {
		const { name, email, username, password } = req.body;
		const user = await User.findOne({ $or: [{ email }, { username }] });

		if (user) {
			return res.status(400).json({ error: 'User already exists' });
		}
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		const newUser = new User({
			name,
			email,
			username,
			password: hashedPassword,
		});
		await newUser.save();

		if (newUser) {
			generateTokenAndSetCookie(newUser._id, res);
			res.status(201).json({
				_id: newUser._id,
				name: newUser.name,
				email: newUser.email,
				username: newUser.username,
				bio: newUser.bio,
				profilePic: newUser.profilePic,
			});
		} else {
			res.status(400).json({ error: 'Invalid user data' });
		}
	} catch (err) {
		res.status(500).json({ error: err.message });
		console.log('Error in signupUser: ', err.message);
	}
};

export const loginUser = async (req, res) => {
	try {
		const { username, password } = req.body;
		const user = await User.findOne({ username });
		if (!user) return res.status(400).json({ error: 'Invalid user' });

		const isPasswordCorrect = await bcrypt.compare(password, user.password);
		if (!isPasswordCorrect) return res.status(400).json({ error: 'Incorrect password' });

		generateTokenAndSetCookie(user._id, res);

		res.status(200).json({
			_id: user._id,
			name: user.name,
			email: user.email,
			username: user.username,
			bio: user.bio,
			profilePic: user.profilePic,
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
		console.log('Error in loginUser: ', error.message);
	}
};

export const logoutUser = (req, res) => {
	try {
		res.cookie('jwt', '', { maxAge: 1 });
		res.status(200).json({ message: 'User logged out successfully' });
	} catch (err) {
		res.status(500).json({ error: err.message });
		console.log('Error in signupUser: ', err.message);
	}
};

// first get the current_user id and user_to_follow id
// then check if both the id are actual users or not
// if current_user is already following the user_to_follow unfollow him else follow him
// to follow -> add user_to_follow id in current user's following, then add current_user's id to user_to_follow followers.
// vice versa in case of unfollowing
export const followUnfollowUser = async (req, res) => {
	try {
		const { id } = req.params;
		const userToModify = await User.findById(id);
		const currentUser = await User.findById(req.user._id);

		if (id === req.user._id.toString())
			return res.status(400).json({ error: 'You cannot follow/unfollow yourself' });

		if (!userToModify || !currentUser) return res.status(400).json({ error: 'User not found' });

		const isFollowing = currentUser.following.includes(id);

		if (isFollowing) {
			// Unfollow user
			await User.findByIdAndUpdate(id, { $pull: { followers: req.user._id } });
			await User.findByIdAndUpdate(req.user._id, { $pull: { following: id } });
			res.status(200).json({ message: 'User unfollowed successfully' });
		} else {
			// Follow user
			await User.findByIdAndUpdate(id, { $push: { followers: req.user._id } });
			await User.findByIdAndUpdate(req.user._id, { $push: { following: id } });
			res.status(200).json({ message: 'User followed successfully' });
		}
	} catch (err) {
		res.status(500).json({ error: err.message });
		console.log('Error in followUnFollowUser: ', err.message);
	}
};
