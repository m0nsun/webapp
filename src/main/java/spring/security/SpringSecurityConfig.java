package spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.web.filter.CharacterEncodingFilter;

import spring.security.jwt.JwtSecurityConfigurer;
import spring.security.jwt.JwtTokenProvider;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    CharacterEncodingFilter encodingFilter;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(encodingFilter, ChannelProcessingFilter.class)
                .httpBasic().disable()
                .csrf().disable()
                .formLogin().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/sh/auth/signIn").permitAll()
                .antMatchers(HttpMethod.POST, "/sh/auth/register").permitAll()
                .antMatchers(HttpMethod.POST,"/sh/auth/refreshToken").permitAll()
                .antMatchers(HttpMethod.PUT, "/sh/auth/exit").hasAnyRole("ADMIN", "USER")

                .antMatchers(HttpMethod.GET, "/sh/test/studentList").permitAll()
                .antMatchers(HttpMethod.GET, "/sh/admin/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST, "/sh/admin/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/sh/profile/*").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.POST, "/sh/profile/updateAll").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.GET, "/sh/timetable").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.GET, "/sh/timetable/day").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.GET, "/sh/timetable/**").hasRole("USER")
                .antMatchers(HttpMethod.POST, "/sh/timetable/**").hasRole("USER")

                .anyRequest().authenticated()
                .and()

                .apply(new JwtSecurityConfigurer(jwtTokenProvider));
    }
}
