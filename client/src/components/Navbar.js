import React, {useContext} from 'react';
import {NavLink} from 'react-router-dom';
import {AuthContext} from '../context/AuthContext';

export const Navbar = () => {
	const auth = useContext(AuthContext);

	const logoutHandler = (event) => {
		event.preventDefault();
		auth.logout();
	};

	return (
		<nav>
			<div className='nav-wrapper blue darken-1' style={{padding: '0 2rem'}}>
				<span className='brand-logo'>Сократить ссылку</span>
				<ul id='nav-mobile' className='right hide-on-med-and-down'>
					<li>
						<NavLink to='/create'>Создать</NavLink>
					</li>
					<li>
						<NavLink to='/links'>Список ссылок</NavLink>
					</li>
					<li>
						<a href='/' onClick={logoutHandler}>
							Выйти
						</a>
					</li>
				</ul>
			</div>
		</nav>
	);
};
