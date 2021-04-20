package net.pranjal.springsecurityjwt.filter;

import net.pranjal.springsecurityjwt.service.MyUserDetailsService;
import net.pranjal.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final String HEADER_KEY = "Authorization";
    private static final String HEADER_VALUE_STARTS_WITH = "Bearer ";

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader(HEADER_KEY);

        String userName = null;
        String jwt = null;

        if (authHeader != null && authHeader.startsWith(HEADER_VALUE_STARTS_WITH)) {
            jwt = authHeader.substring(HEADER_VALUE_STARTS_WITH.length());
            userName = jwtUtil.extractUsername(jwt);
        }

        if (userName != null && getContext().getAuthentication() == null) {

            UserDetails userDetails = myUserDetailsService.loadUserByUsername(userName);

            if (jwtUtil.isValidToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                        = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
